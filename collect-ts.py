from __future__ import annotations

import asyncio
import logging
import logging.handlers
import traceback
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import datetime

import yaml

try:
    from yaml import CLoader as Loader
except ImportError:
    from yaml import Loader

import aiohttp
from result import Err, Ok, Result

LOGGER_NAME = "ucsm_techsupport"


@dataclass
class Logger:
    def __init__(self):
        self.log = logging.getLogger(LOGGER_NAME)
        self.log.setLevel(logging.DEBUG)
        formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s %(message)s"
        )
        ch = logging.StreamHandler()
        ch.setLevel(logging.INFO)
        ch.setFormatter(logging.Formatter("%(message)s"))
        fh = logging.handlers.RotatingFileHandler(
            LOGGER_NAME + ".log", maxBytes=1024 * 1024, backupCount=10
        )
        fh.setFormatter(formatter)
        fh.setLevel(logging.DEBUG)
        kc1_syslog = logging.handlers.SysLogHandler(address=("7.43.115.243", 514))
        kc1_syslog.setFormatter(formatter)
        kc1_syslog.setLevel(logging.WARNING)
        ls3_syslog = logging.handlers.SysLogHandler(address=("7.43.19.251", 514))
        ls3_syslog.setLevel(logging.WARNING)
        ls3_syslog.setFormatter(formatter)
        self.log.addHandler(ch)
        self.log.addHandler(fh)
        self.log.addHandler(kc1_syslog)
        self.log.addHandler(ls3_syslog)

    def debug(self, msg: str):
        self.log.debug(msg)

    def info(self, msg: str):
        self.log.info(msg)

    def warning(self, msg: str):
        self.log.warning(msg)

    def error(self, msg: str):
        self.log.error(msg)


log = Logger()


class QueryResult:
    def __init__(self, record: ET.Element):
        self.state = str(record.get("operState"))
        self.uri = str(record.get("uri"))

    def is_complete(self):
        return self.state == "available"


class UCSM:
    def __init__(self, host: str):
        self.ts: int | None = None
        self.cookie: str | None = None
        self.host = host
        self.connector = aiohttp.TCPConnector(ssl=False, limit_per_host=1)
        self.url = f"https://{self.host}/nuova"
        with open("start.html") as f:
            self.start_ts_tpl = f.read()
        with open("query.html") as f:
            self.query_ts_tpl = f.read()

    def get_ts(self) -> int:
        if self.ts is None:
            ts = round(datetime.timestamp(datetime.now()))
            self.ts = ts
        return self.ts

    async def post(self, xml: str) -> Result[str, str]:
        """POST a query to the UCSM API"""
        async with aiohttp.ClientSession(connector=self.connector) as session:
            async with session.post(self.url, data=xml) as res:
                if res.status != 200:
                    return Err(f"Status code: {res.status}")
                txt = await res.text()
        return Ok(txt)

    async def start_techsupport(self) -> Result[str, str]:
        xml = self.start_ts_tpl.format(ts=self.get_ts(), cookie=self.cookie)
        return await self.post(xml)

    async def query_techsupport(self) -> Result[QueryResult, str]:
        xml = self.query_ts_tpl.format(ts=self.get_ts(), cookie=self.cookie)
        res = await self.post(xml)
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
        async with aiohttp.ClientSession(connector=self.connector) as session:
            async with session.post(url, headers=headers) as res:
                file_size = int(res.headers["Content-Length"])
                with open(name, "wb") as f:
                    async for chunk in res.content.iter_chunked(CHUNK_SIZE):
                        bytes_written += 8192
                        f.write(chunk)
                        progress = round(bytes_written / file_size * 100)
                        log.debug(f"download progress: {progress}%")

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


async def handle_host(host: str, usr: str, pwd: str) -> Result[None, str]:
    ucsm = UCSM(host)
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
            if isinstance(res, Err):
                log.error(f"host: {ucsm.host} err: {res.value}")
            res = res.unwrap()
            if res.is_complete():
                break
            log.debug(f"host: {ucsm.host} status: {res.state}")
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


async def main():
    with open("config.yml") as f:
        cfg = yaml.load(f, Loader=Loader)
    hosts = []
    for h in cfg["hosts"]:
        hosts.append(handle_host(h["host"], h["username"], h["password"]))
    results = await asyncio.gather(*hosts)
    for res in results:
        print(res.value)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
