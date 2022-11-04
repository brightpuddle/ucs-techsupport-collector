from __future__ import annotations

import asyncio
import json
import traceback
import xml.etree.ElementTree as ET
from base64 import b64encode
from dataclasses import dataclass, field
from datetime import datetime
from email.utils import formatdate
from urllib.parse import urlparse

import aiofiles
import yaml
from aiohttp.client_exceptions import ServerDisconnectedError
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from rich.console import Console
from rich.progress import Progress

try:
    from yaml import CLoader as Loader
except ImportError:
    from yaml import Loader

import aiohttp
from result import Err, Ok, Result

LOGGER_NAME = "ucsm_techsupport"
INTERSIGHT_API = "https://www.intersight.com/api/v1"


@dataclass
class Logger:
    def __init__(self, console: Console):
        self.ch = console
        f = open(f"{LOGGER_NAME}.log", "w+")
        self.fh = Console(stderr=True, file=f)

    def debug(self, msg: str):
        self.fh.log(f"DEBUG: {msg}")

    def info(self, msg: str):
        self.fh.log(f"INFO: {msg}")
        self.ch.log(f"[green]INFO:[/] {msg}")

    def warning(self, msg: str):
        self.fh.log(f"WARNING: {msg}")
        self.ch.log(f"[yellow]WARNING:[/] {msg}")

    def error(self, msg: str):
        self.fh.log(f"ERROR: {msg}")
        self.ch.log(f"[red]ERROR:[/] {msg}")


@dataclass
class UCSMHost:
    host: str
    username: str
    password: str
    source: str = ""


@dataclass
class IntersightHost:
    vip: str
    source: str = ""


@dataclass
class Config:
    api_key: str
    secret_key_file: str
    secret_key_file_password: str | None = None
    hosts: list[UCSMHost | IntersightHost] = field(default_factory=list)

    @classmethod
    def from_file(cls, filename: str) -> Config:
        with open(filename) as f:
            cfg = yaml.load(f, Loader=Loader)
        self = cls(**cfg)
        self.hosts = []
        for host_cfg in cfg.get("hosts", []):
            if host_cfg.get("source") == "intersight":
                self.hosts.append(IntersightHost(**host_cfg))
            if host_cfg.get("source") == "ucsm":
                self.hosts.append(UCSMHost(**host_cfg))
        return self


class ServerDisconnectErr(Err):
    pass


@dataclass
class IntersightQueryResult:
    status: str
    link: str

    def is_complete(self) -> bool:
        return self.status == "Completed"


@dataclass
class Intersight:
    cfg: Config
    host: IntersightHost
    progress: Progress
    log: Logger
    session: aiohttp.ClientSession | None = None
    cookie: str | None = None
    pid: str | None = None
    sn: str | None = None
    moid: str | None = None
    status: str | None = None

    def __post_init__(self):
        self.name = self.host.vip
        msg = f"Generating techsupport for {self.name}..."
        self.task = self.progress.add_task(msg, total=None)
        pwd = None
        if self.cfg.secret_key_file_password is not None:
            pwd = bytes(self.cfg.secret_key_file_password, "utf-8")
        with open(self.cfg.secret_key_file, "rb") as f:
            self.secret_key = serialization.load_pem_private_key(
                f.read(),
                password=pwd,
                backend=default_backend(),
            )

    async def start(self) -> Result[None, str]:
        # conn = aiohttp.TCPConnector(ssl=True, limit_per_host=1)
        # hour long timeout to give download time to complete
        timeout = aiohttp.ClientTimeout(total=3600)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            self.session = session

            # PID and serial number
            self.log.info(f"fetching pid and sn for {self.name}")
            res = await self.get_pid_serial()
            if isinstance(res, Err):
                return Err(f"error fetching pid and sn on {self.name}: {res.value}")

            # Start techsupport
            self.log.info(f"starting techsupport for {self.name}")
            res = await self.start_techsupport()
            if isinstance(res, Err):
                msg = f"error starting techsupport for {self.name}: {res.value}"
                return Err(msg)
            while True:
                res = await self.query_techsupport()
                if isinstance(res, Err):
                    self.log.error(f"host: {self.name} err: {res.value}")
                    return res
                res = res.unwrap()
                if res.is_complete():
                    break
                await asyncio.sleep(5)
            self.log.info(f"downloading techsupport for {self.name}")
            await self.download_techsupport()
        return Ok()

    async def get_pid_serial(self) -> Result[None, str]:
        query = f"$filter=contains(DeviceIpAddress,'{self.host.vip}')"
        url = f"{INTERSIGHT_API}/asset/DeviceRegistrations?{query}"
        res = await self.get(url)
        if isinstance(res, Err):
            return res
        data = res.unwrap()
        try:
            self.pid = data["Results"][0]["Pid"][0]
            self.log.debug(f"PID: {self.pid}")
            self.sn = data["Results"][0]["Serial"][0]
            self.log.debug(f"SN: {self.sn}")
        except Exception:
            self.log.debug(json.dumps(data))
            return Err("unable to read pid or SN from Intersight response")
        return Ok()

    async def start_techsupport(self) -> Result[None, str]:
        url = f"{INTERSIGHT_API}/techsupportmanagement/TechSupportBundles"
        if self.pid is None or self.sn is None:
            return Err("called start_techsupport with no pid")
        body = {
            "Serial": self.sn,
            "Pid": self.pid,
            "PlatformType": "UCSFI",
        }
        res = await self.post(url, body)
        if isinstance(res, Err):
            return res
        data = res.unwrap()
        try:
            self.moid = data["TechSupportStatus"]["Moid"]
        except Exception:
            return Err("cannot read moid from start_techsupport response")
        return Ok()

    async def query_techsupport(self) -> Result[IntersightQueryResult, str]:
        if self.moid is None:
            return Err("called query_techsupport with no moid")
        url = f"{INTERSIGHT_API}/techsupportmanagement/TechSupportStatuses/{self.moid}"
        res = await self.get(url)
        if isinstance(res, Err):
            return res
        data = res.unwrap()
        try:
            self.status = data["Status"]
            self.download_url = data["TechsupportDownloadUrl"]
        except Exception:
            return Err("cannot read query_techsupport response")
        return Ok(IntersightQueryResult(self.status, self.download_url))

    async def download_techsupport(self) -> Result[None, str]:
        if self.download_url is None:
            return Err("download called with no valid link")
        name = f"{self.name}-{self.moid}.tar"
        CHUNK_SIZE = 8192
        bytes_written = 0
        if self.session is None:
            return Err("no session for download")
        headers = self.get_auth_headers("GET", self.download_url, None)
        self.log.info(f"downloading {name} for {self.name}")
        async with self.session.get(self.download_url, headers=headers) as res:
            file_size = int(res.headers["Content-Length"])
            file_size_mb = round(int(res.headers["Content-Length"]) / 1024 / 1024)
            self.progress.update(
                self.task,
                description=f"Downloading {file_size_mb}MB for {self.name}...",
                total=100,
            )
            async with aiofiles.open(name, "wb") as f:
                async for chunk in res.content.iter_chunked(CHUNK_SIZE):
                    bytes_written += CHUNK_SIZE
                    await f.write(chunk)
                    self.progress.update(
                        self.task, completed=round(bytes_written / file_size * 100)
                    )
        self.progress.update(
            self.task, description=f"{self.name} complete.", completed=100
        )
        return Ok()

    async def get(self, url: str) -> Result[dict, str]:
        if self.session is None:
            return Err("GET with no session")
        headers = self.get_auth_headers("GET", url, None)
        async with self.session.get(url, headers=headers) as res:
            if res.status >= 300:
                return Err(f"Status code: {res.status}")
            res_data = await res.json()
            return Ok(res_data)

    async def post(self, url: str, data: dict[str, str]) -> Result[dict, str]:
        if self.session is None:
            return Err("POST with no session")
        body = json.dumps(data)
        headers = self.get_auth_headers("POST", url, body)
        async with self.session.post(url, data=body, headers=headers) as res:
            if res.status >= 300:
                return Err(f"Status code: {res.status}")
            res_data = await res.json()
            return Ok(res_data)

    def get_auth_headers(self, method, url, body) -> dict[str, str]:
        date = formatdate(timeval=None, localtime=False, usegmt=True)
        # date = "Tue, 07 Aug 2018 04:03:47 GMT"

        digest = self.get_sha256_digest(body)

        parsed_url = urlparse(url)
        path = parsed_url.path or "/"

        if parsed_url.query:
            path += "?" + parsed_url.query

        signing_headers = {
            "Date": date,
            "Host": parsed_url.hostname,
            "Content-Type": "application/json",
            "Digest": "SHA-256=%s" % b64encode(digest).decode("ascii"),
        }

        auth_header = self.get_auth_header(
            signing_headers,
            method,
            path,
            self.cfg.api_key,
            self.secret_key,
        )

        return {
            "Digest": "SHA-256=%s" % b64encode(digest).decode("ascii"),
            "Date": date,
            "Authorization": auth_header,
            "Host": parsed_url.hostname or "",
            "Content-Type": "application/json",
        }

    @classmethod
    def get_sha256_digest(cls, data) -> bytes:
        hasher = hashes.Hash(hashes.SHA256(), default_backend())
        if data is not None:
            hasher.update(data.encode())
        return hasher.finalize()

    @classmethod
    def prepare_string_to_sign(cls, req_tgt, hdrs) -> str:
        signature_string = "(request-target): " + req_tgt.lower() + "\n"
        for i, (key, value) in enumerate(hdrs.items()):
            signature_string += key.lower() + ": " + value
            if i < len(hdrs.items()) - 1:
                signature_string += "\n"

        return signature_string

    @classmethod
    def get_rsasig_b64(cls, key, string_to_sign) -> bytes:
        return b64encode(key.sign(string_to_sign, padding.PKCS1v15(), hashes.SHA256()))

    @classmethod
    def get_auth_header(cls, signing_headers, method, path, api_key_id, secret_key):
        string_to_sign = cls.prepare_string_to_sign(
            method + " " + path, signing_headers
        )
        b64_signed_auth_digest = cls.get_rsasig_b64(secret_key, string_to_sign.encode())
        auth_str = (
            'Signature keyId="'
            + api_key_id
            + '",'
            + 'algorithm="rsa-sha256",headers="(request-target)'
        )
        for key in signing_headers:
            auth_str += " " + key.lower()
        auth_str += '", signature="' + b64_signed_auth_digest.decode("ascii") + '"'
        return auth_str


class UCSMQueryResult:
    def __init__(self, record: ET.Element):
        self.state = str(record.get("operState"))
        self.uri = str(record.get("uri"))

    def is_complete(self):
        return self.state == "available"


@dataclass
class UCSM:
    cfg: Config
    host: UCSMHost
    progress: Progress
    log: Logger
    session: aiohttp.ClientSession | None = None
    ts: int | None = None
    cookie: str | None = None

    def __post_init__(self):
        self.name = self.host.host
        self.url = f"https://{self.host.host}/nuova"
        msg = f"Generating techsupport for {self.name}..."
        self.task = self.progress.add_task(msg, total=None)
        with open("start.html") as f:
            self.start_ts_tpl = f.read()
        with open("query.html") as f:
            self.query_ts_tpl = f.read()

    async def start(self) -> Result[None, str]:
        conn = aiohttp.TCPConnector(ssl=False, limit_per_host=1)
        # hour long timeout to give download time to complete
        timeout = aiohttp.ClientTimeout(total=3600)
        async with aiohttp.ClientSession(connector=conn, timeout=timeout) as session:
            self.session = session
            self.log.info(f"logging in to {self.name}")
            try:
                res = await self.auth()
                if isinstance(res, Err):
                    return Err(f"error logging into {self.name}: {res.value}")
                self.log.info(f"starting techsupport for {self.name}")
                res = await self.start_techsupport()
                if isinstance(res, Err):
                    msg = f"error starting techsupport for {self.name}: {res.value}"
                    return Err(msg)
                while True:
                    res = await self.query_techsupport()
                    if isinstance(res, ServerDisconnectErr):
                        await asyncio.sleep(10)
                        continue
                    if isinstance(res, Err):
                        self.log.error(f"host: {self.name} err: {res.value}")
                        return res
                    res = res.unwrap()
                    if res.is_complete():
                        break
                    await asyncio.sleep(5)
                self.log.info(f"downloading techsupport for {self.name}")
                await self.download_techsupport(res.uri)
            except Exception as e:
                raise e
            finally:
                if self.cookie:
                    try:
                        res = await self.logout()
                        if isinstance(res, Err):
                            return res
                    except Exception as e:
                        traceback.print_exc()
                        return Err(str(e))
        return Ok()

    def get_ts(self) -> int:
        if self.ts is None:
            ts = round(datetime.timestamp(datetime.now()))
            self.ts = ts
        return self.ts

    async def post(self, xml: str) -> Result[str, str]:
        """POST a query to the UCSM API"""
        if self.session is None:
            return Err("post called without session")
        async with self.session.post(self.url, data=xml) as res:
            if res.status >= 300:
                return Err(f"Status code: {res.status}")
            txt = await res.text()
        return Ok(txt)

    async def start_techsupport(self) -> Result[str, str]:
        xml = self.start_ts_tpl.format(ts=self.get_ts(), cookie=self.cookie)
        return await self.post(xml)

    async def query_techsupport(self) -> Result[UCSMQueryResult, str]:
        xml = self.query_ts_tpl.format(ts=self.get_ts(), cookie=self.cookie)
        try:
            res = await self.post(xml)
        except ServerDisconnectedError:
            return ServerDisconnectErr("Server disconnected")
        if isinstance(res, Err):
            return res
        txt = res.unwrap()
        root = ET.fromstring(txt)
        record = root.find("./outConfigs/sysdebugTechSupport")
        if record is None:
            return Err(f"xpath query failed on TS response: {txt}")
        oper_state = record.get("operState")
        if oper_state not in ["available", "in-progress"]:
            return Err(f"unexpected techsupport state {oper_state}")
        return Ok(UCSMQueryResult(record))

    async def download_techsupport(self, uri: str) -> Result[None, str]:
        url = f"https://{self.host.host}/{uri}"
        name = uri.split("/")[-1]
        headers = {"Cookie": f"ucsm-cookie={self.cookie}"}
        CHUNK_SIZE = 8192
        bytes_written = 0
        if self.session is None:
            return Err("no session for download")
        self.log.info(f"downloading {name} for {self.name}")
        async with self.session.post(url, headers=headers) as res:
            file_size = int(res.headers["Content-Length"])
            file_size_mb = round(int(res.headers["Content-Length"]) / 1024 / 1024)
            self.progress.update(
                self.task,
                description=f"Downloading {file_size_mb}MB for {self.name}...",
                total=100,
            )
            async with aiofiles.open(name, "wb") as f:
                async for chunk in res.content.iter_chunked(CHUNK_SIZE):
                    bytes_written += CHUNK_SIZE
                    await f.write(chunk)
                    self.progress.update(
                        self.task, completed=round(bytes_written / file_size * 100)
                    )
        self.progress.update(
            self.task, description=f"{self.name} complete.", completed=100
        )
        return Ok()

    async def auth(self) -> Result[None, str]:
        usr = self.host.username
        pwd = self.host.password
        xml = f'<aaaLogin inName="{usr}" inPassword="{pwd}" />'
        res = await self.post(xml)
        if isinstance(res, Err):
            return res
        res = res.unwrap()
        root = ET.fromstring(res)
        self.cookie = root.get("outCookie")
        if self.cookie is None:
            errMsg = root.get("errorDescr")
            if errMsg is None:
                return Err(f"login: outCookie not found in response data {res}")
            return Err(errMsg)
        return Ok()

    async def logout(self) -> Result[str, str]:
        xml = f'<aaaLogout inCookie="{self.cookie}" />'
        return await self.post(xml)


async def main() -> None:
    cfg = Config.from_file("config.yaml")
    hosts = []
    c = Console()
    log = Logger(c)
    with Progress(console=c) as p:
        for h in cfg.hosts:
            if isinstance(h, UCSMHost):
                hosts.append(UCSM(cfg, h, p, log).start())
            elif isinstance(h, IntersightHost):
                hosts.append(Intersight(cfg, h, p, log).start())
        results = await asyncio.gather(*hosts)
        for res in results:
            if isinstance(res, Err):
                log.error(res.value)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
