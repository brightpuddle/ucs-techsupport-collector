from __future__ import annotations

import asyncio
import traceback
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import datetime

import aiofiles
import yaml
from aiohttp.client_exceptions import ServerDisconnectedError
from rich.console import Console
from rich.progress import Progress

try:
    from yaml import CLoader as Loader
except ImportError:
    from yaml import Loader

import aiohttp
from result import Err, Ok, Result

LOGGER_NAME = "ucsm_techsupport"


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


class QueryResult:
    def __init__(self, record: ET.Element):
        self.state = str(record.get("operState"))
        self.uri = str(record.get("uri"))

    def is_complete(self):
        return self.state == "available"


class ServerDisconnectErr(Err):
    pass


class UCSM:
    def __init__(
        self, host: str, session: aiohttp.ClientSession, p: Progress, log: Logger
    ):
        self.ts: int | None = None
        self.cookie: str | None = None
        self.host = host
        self.url = f"https://{self.host}/nuova"
        self.progress = p
        self.log = log
        self.task = p.add_task(f"Generating techsupport for {host}...", total=None)
        self.session = session
        with open("start.html") as f:
            self.start_ts_tpl = f.read()
        with open("query.html") as f:
            self.query_ts_tpl = f.read()

    @classmethod
    async def start(
        cls, host: str, usr: str, pwd: str, p: Progress, log: Logger
    ) -> Result[None, str]:
        conn = aiohttp.TCPConnector(ssl=False, limit_per_host=1)
        # hour long timeout to give download time to complete
        timeout = aiohttp.ClientTimeout(total=3600)
        async with aiohttp.ClientSession(connector=conn, timeout=timeout) as session:
            ucsm = cls(host, session, p, log)
            log.info(f"logging in to {ucsm.host}")
            try:
                res = await ucsm.login(usr, pwd)
                if isinstance(res, Err):
                    return Err(f"error logging into {ucsm.host}: {res.value}")
                log.info(f"starting techsupport for {ucsm.host}")
                res = await ucsm.start_techsupport()
                if isinstance(res, Err):
                    return Err(f"error logging into {ucsm.host}: {res.value}")
                while True:
                    res = await ucsm.query_techsupport()
                    if isinstance(res, ServerDisconnectErr):
                        await asyncio.sleep(10)
                        continue
                    if isinstance(res, Err):
                        log.error(f"host: {ucsm.host} err: {res.value}")
                        return res
                    res = res.unwrap()
                    if res.is_complete():
                        break
                    await asyncio.sleep(5)
                log.info(f"downloading techsupport for {ucsm.host}")
                await ucsm.download_techsupport(res.uri)
            except Exception as e:
                raise e
            finally:
                if ucsm.cookie:
                    try:
                        res = await ucsm.logout()
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
        async with self.session.post(self.url, data=xml) as res:
            if res.status != 200:
                return Err(f"Status code: {res.status}")
            txt = await res.text()
        return Ok(txt)

    async def start_techsupport(self) -> Result[str, str]:
        xml = self.start_ts_tpl.format(ts=self.get_ts(), cookie=self.cookie)
        return await self.post(xml)

    async def query_techsupport(self) -> Result[QueryResult, str]:
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
        return Ok(QueryResult(record))

    async def download_techsupport(self, uri: str):
        url = f"https://{self.host}/{uri}"
        name = uri.split("/")[-1]
        headers = {"Cookie": f"ucsm-cookie={self.cookie}"}
        CHUNK_SIZE = 8192
        bytes_written = 0
        async with self.session.post(url, headers=headers) as res:
            file_size = int(res.headers["Content-Length"])
            file_size_mb = round(int(res.headers["Content-Length"]) / 1024 / 1024)
            self.progress.update(
                self.task,
                description=f"Downloading {file_size_mb}MB for {self.host}...",
                total=100,
            )
            async with aiofiles.open(name, "wb") as f:
                async for chunk in res.content.iter_chunked(CHUNK_SIZE):
                    bytes_written += 8192
                    await f.write(chunk)
                    self.progress.update(
                        self.task, completed=round(bytes_written / file_size * 100)
                    )
        self.progress.update(
            self.task, description=f"{self.host} complete.", completed=100
        )

    async def login(self, usr: str, pwd: str) -> Result[None, str]:
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


async def main():
    with open("config.yml") as f:
        cfg = yaml.load(f, Loader=Loader)
    hosts = []
    c = Console()
    log = Logger(c)
    with Progress(console=c) as p:
        for h in cfg["hosts"]:
            hosts.append(UCSM.start(h["host"], h["username"], h["password"], p, log))
        results = await asyncio.gather(*hosts)
        for res in results:
            log.info(res.value)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
