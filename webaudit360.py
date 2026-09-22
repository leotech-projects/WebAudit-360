#!/usr/bin/env python3
"""WebAudit 360 — auditoria automatizada e não destrutiva de sites autorizados."""

from __future__ import annotations

import argparse
import concurrent.futures
import dataclasses
import datetime as dt
import json
import re
import socket
import ssl
import sys
import time
from collections import Counter, deque
from pathlib import Path
from typing import Any
from urllib.parse import urldefrag, urljoin, urlparse

import requests
from bs4 import BeautifulSoup

UA = "WebAudit360/1.0 (+authorized non-destructive website audit)"
TIMEOUT = 15
SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
]
VIEWPORTS = [
    (1920,1080),(1366,768),(1024,768),(768,1024),
    (430,932),(390,844),(360,800)
]

@dataclasses.dataclass
class PageResult:
    url: str
    status: int | None = None
    elapsed_ms: float | None = None
    title: str = ""
    meta_description: str = ""
    h1: list[str] = dataclasses.field(default_factory=list)
    canonical: str = ""
    content_type: str = ""
    internal_links: list[str] = dataclasses.field(default_factory=list)
    external_links: list[str] = dataclasses.field(default_factory=list)
    images: int = 0
    images_missing_alt: int = 0
    forms: list[dict[str, Any]] = dataclasses.field(default_factory=list)
    security_headers: dict[str, str | None] = dataclasses.field(default_factory=dict)
    cookies: list[dict[str, Any]] = dataclasses.field(default_factory=list)
    issues: list[dict[str, str]] = dataclasses.field(default_factory=list)
    error: str | None = None

class WebAudit360:
    def __init__(self, url: str, max_pages: int, timeout: int, output: Path, browser: bool):
        if not re.match(r"^https?://", url, re.I):
            url = "https://" + url
        self.base_url = url.rstrip("/")
        self.base = urlparse(self.base_url)
        self.max_pages = max_pages
        self.timeout = timeout
        self.output = output
        self.browser_enabled = browser
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": UA})
        self.pages: list[PageResult] = []
        self.links: set[str] = set()
        self.started = dt.datetime.now(dt.timezone.utc)

    def same_site(self, url: str) -> bool:
        p = urlparse(url)
        return p.netloc.lower() == self.base.netloc.lower() and p.scheme in {"http","https"}

    def normalize(self, href: str, source: str) -> str | None:
        if not href or href.startswith(("mailto:","tel:","javascript:","data:","#")):
            return None
        url, _ = urldefrag(urljoin(source, href))
        p = urlparse(url)
        if p.scheme not in {"http","https"}:
            return None
        if re.search(r"\.(?:jpg|jpeg|png|gif|webp|svg|pdf|zip|rar|7z|mp4|mp3|docx?|xlsx?|pptx?)(?:\?|$)", p.path, re.I):
            self.links.add(url)
            return None
        return url.rstrip("/") or url

    @staticmethod
    def issue(severity: str, category: str, description: str) -> dict[str,str]:
        return {"severity": severity, "category": category, "description": description}

    def fetch(self, url: str):
        start = time.perf_counter()
        try:
            r = self.session.get(url, timeout=self.timeout, allow_redirects=True)
            return r, round((time.perf_counter()-start)*1000,1), None
        except requests.RequestException as exc:
            return None, round((time.perf_counter()-start)*1000,1), str(exc)

    def inspect_cookies(self, response: requests.Response) -> list[dict[str,Any]]:
        out=[]
        for c in response.cookies:
            rest={str(k).lower():v for k,v in getattr(c,"_rest",{}).items()}
            out.append({
                "name": c.name,
                "secure": bool(c.secure),
                "httponly": "httponly" in rest,
                "samesite": rest.get("samesite")
            })
        return out

    def analyze_page(self, url: str) -> tuple[PageResult,list[str]]:
        result=PageResult(url=url)
        r, ms, err=self.fetch(url)
        result.elapsed_ms=ms
        if err or r is None:
            result.error=err
            result.issues.append(self.issue("ALTA","Funcionalidade",f"Falha ao carregar: {err}"))
            return result, []

        result.status=r.status_code
        result.content_type=r.headers.get("content-type","")
        result.security_headers={h:r.headers.get(h) for h in SECURITY_HEADERS}
        result.cookies=self.inspect_cookies(r)

        if r.status_code >= 400:
            sev="ALTA" if r.status_code >= 500 else "MÉDIA"
            result.issues.append(self.issue(sev,"HTTP",f"HTTP {r.status_code}"))

        if "text/html" not in result.content_type.lower():
            return result, []

        soup=BeautifulSoup(r.text,"html.parser")
        result.title=soup.title.get_text(" ",strip=True) if soup.title else ""
        meta=soup.find("meta",attrs={"name":re.compile("^description$",re.I)})
        result.meta_description=(meta.get("content") or "").strip() if meta else ""
        result.h1=[x.get_text(" ",strip=True) for x in soup.find_all("h1")]
        can=soup.find("link",rel=lambda x:x and "canonical" in x)
        result.canonical=(can.get("href") or "").strip() if can else ""

        imgs=soup.find_all("img")
        result.images=len(imgs)
        result.images_missing_alt=sum(1 for img in imgs if not (img.get("alt") or "").strip())

        discovered=[]
        for a in soup.find_all("a",href=True):
            u=self.normalize(a.get("href",""),r.url)
            if not u:
                continue
            self.links.add(u)
            if self.same_site(u):
                result.internal_links.append(u)
                discovered.append(u)
            else:
                result.external_links.append(u)

        for form in soup.find_all("form"):
            fields=[]
            for el in form.find_all(["input","select","textarea","button"]):
                fields.append({
                    "tag":el.name,
                    "type":el.get("type",""),
                    "name":el.get("name",""),
                    "required":el.has_attr("required"),
                    "aria_label":el.get("aria-label","")
                })
            result.forms.append({
                "action":urljoin(r.url,form.get("action") or r.url),
                "method":(form.get("method") or "GET").upper(),
                "fields":fields
            })

        if not result.title:
            result.issues.append(self.issue("MÉDIA","SEO","Página sem <title>."))
        elif len(result.title)>65:
            result.issues.append(self.issue("BAIXA","SEO","Title possivelmente longo (>65 caracteres)."))
        if not result.meta_description:
            result.issues.append(self.issue("BAIXA","SEO","Meta description ausente."))
        if len(result.h1)==0:
            result.issues.append(self.issue("MÉDIA","SEO/Acessibilidade","H1 ausente."))
        if len(result.h1)>1:
            result.issues.append(self.issue("BAIXA","SEO",f"Múltiplos H1 encontrados ({len(result.h1)})."))
        if result.images_missing_alt:
            result.issues.append(self.issue("MÉDIA","Acessibilidade",f"{result.images_missing_alt} imagem(ns) sem alt significativo."))
        if result.elapsed_ms and result.elapsed_ms>2500:
            result.issues.append(self.issue("MÉDIA","Performance",f"Resposta inicial lenta: {result.elapsed_ms:.0f} ms."))
        for h,v in result.security_headers.items():
            if not v:
                result.issues.append(self.issue("MÉDIA","Segurança",f"Header ausente: {h}."))
        if r.url.startswith("http://"):
            result.issues.append(self.issue("ALTA","Segurança","Página final servida sem HTTPS."))

        unlabeled=0
        for inp in soup.find_all(["input","select","textarea"]):
            typ=(inp.get("type") or "").lower()
            if typ in {"hidden","submit","button","image","reset"}:
                continue
            ident=inp.get("id")
            has_label=bool(ident and soup.find("label",attrs={"for":ident}))
            accessible=has_label or inp.get("aria-label") or inp.get("aria-labelledby") or inp.get("title")
            if not accessible:
                unlabeled+=1
        if unlabeled:
            result.issues.append(self.issue("MÉDIA","Acessibilidade",f"{unlabeled} campo(s) possivelmente sem rótulo acessível."))

        return result, discovered

    def sitemap_urls(self) -> list[str]:
        """Lê sitemap.xml para descobrir rotas de SPAs e páginas não presentes no HTML inicial."""
        url=f"{self.base.scheme}://{self.base.netloc}/sitemap.xml"
        try:
            r=self.session.get(url,timeout=self.timeout,allow_redirects=True)
            if r.status_code >= 400:
                return []
            urls=[]
            for raw in re.findall(r"<loc>\\s*(.*?)\\s*</loc>", r.text, flags=re.I | re.S):
                loc=raw.strip().replace("&amp;", "&")
                u=self.normalize(loc, self.base_url)
                if u and self.same_site(u):
                    urls.append(u)
            return list(dict.fromkeys(urls))
        except requests.RequestException:
            return []

    def crawl(self):
        seeds=[self.base_url]
        sitemap=self.sitemap_urls()
        if sitemap:
            print(f"[sitemap] {len(sitemap)} URL(s) pública(s) descoberta(s)")
            seeds.extend(sitemap)
        queue=deque(dict.fromkeys(seeds))
        seen=set()
        while queue and len(seen)<self.max_pages:
            url=queue.popleft()
            if url in seen:
                continue
            seen.add(url)
            print(f"[crawl {len(seen)}/{self.max_pages}] {url}")
            page, found=self.analyze_page(url)
            self.pages.append(page)
            for u in found:
                if u not in seen and u not in queue:
                    queue.append(u)

    def special_files(self):
        data={}
        for path in ("/robots.txt","/sitemap.xml"):
            url=f"{self.base.scheme}://{self.base.netloc}{path}"
            try:
                r=self.session.get(url,timeout=self.timeout,allow_redirects=True)
                data[path]={"url":r.url,"status":r.status_code,"content_type":r.headers.get("content-type","")}
            except requests.RequestException as exc:
                data[path]={"url":url,"error":str(exc)}
        return data

    def tls_info(self):
        if self.base.scheme!="https":
            return {"tested":False,"reason":"Base URL não usa HTTPS."}
        host=self.base.hostname
        port=self.base.port or 443
        try:
            ctx=ssl.create_default_context()
            with socket.create_connection((host,port),timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock,server_hostname=host) as ssock:
                    cert=ssock.getpeercert()
                    return {
                        "tested":True,
                        "protocol":ssock.version(),
                        "cipher":ssock.cipher(),
                        "notBefore":cert.get("notBefore"),
                        "notAfter":cert.get("notAfter"),
                    }
        except Exception as exc:
            return {"tested":True,"error":str(exc)}

    def check_links(self):
        urls=sorted(self.links)
        print(f"[links] Verificando {len(urls)} URLs descobertas...")
        def check(url):
            try:
                start=time.perf_counter()
                r=self.session.head(url,timeout=self.timeout,allow_redirects=True)
                if r.status_code in {403,405}:
                    r=self.session.get(url,timeout=self.timeout,allow_redirects=True,stream=True)
                return {
                    "url":url,"status":r.status_code,"final_url":r.url,
                    "elapsed_ms":round((time.perf_counter()-start)*1000,1)
                }
            except requests.RequestException as exc:
                return {"url":url,"status":None,"error":str(exc)}
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
            return list(ex.map(check,urls))

    def browser_checks(self):
        if not self.browser_enabled:
            return {"tested":False,"reason":"Execute com --browser para habilitar Playwright."}
        try:
            from playwright.sync_api import sync_playwright
        except Exception as exc:
            return {"tested":False,"reason":f"Playwright indisponível: {exc}"}

        self.output.mkdir(parents=True,exist_ok=True)
        results={"tested":True,"pages":[]}
        targets=[p.url for p in self.pages[:min(10,len(self.pages))]]
        with sync_playwright() as pw:
            browser=pw.chromium.launch(headless=True)
            for url in targets:
                pdata={"url":url,"viewports":[]}
                for width,height in VIEWPORTS:
                    page=browser.new_page(viewport={"width":width,"height":height})
                    errors=[]
                    page.on("console",lambda msg,e=errors:e.append(msg.text) if msg.type=="error" else None)
                    page.on("pageerror",lambda exc,e=errors:e.append(str(exc)))
                    try:
                        start=time.perf_counter()
                        response=page.goto(url,wait_until="networkidle",timeout=max(30000,self.timeout*1000))
                        load_ms=round((time.perf_counter()-start)*1000,1)
                        overflow=page.evaluate("document.documentElement.scrollWidth > document.documentElement.clientWidth")
                        safe=re.sub(r"[^a-zA-Z0-9]+","_",urlparse(url).path.strip("/") or "home")[:60]
                        shot=self.output/f"screenshot_{safe}_{width}x{height}.png"
                        page.screenshot(path=str(shot),full_page=True)
                        pdata["viewports"].append({
                            "size":f"{width}x{height}",
                            "status":response.status if response else None,
                            "load_ms":load_ms,
                            "horizontal_overflow":bool(overflow),
                            "console_errors":errors[:20],
                            "screenshot":shot.name
                        })
                    except Exception as exc:
                        pdata["viewports"].append({"size":f"{width}x{height}","error":str(exc)})
                    finally:
                        page.close()
                results["pages"].append(pdata)
            browser.close()
        return results

    def summary(self, link_results):
        issues=[i for p in self.pages for i in p.issues]
        severity=Counter(i["severity"] for i in issues)
        category=Counter(i["category"] for i in issues)
        broken=[x for x in link_results if x.get("status") is None or (isinstance(x.get("status"),int) and x["status"]>=400)]
        penalties={"CRÍTICA":20,"ALTA":10,"MÉDIA":4,"BAIXA":1,"INFORMATIVA":0}
        score=max(0,100-sum(penalties.get(i["severity"],0) for i in issues)/max(1,len(self.pages)))
        return {
            "pages_analyzed":len(self.pages),
            "links_discovered":len(self.links),
            "broken_or_blocked_links":len(broken),
            "issues_total":len(issues),
            "issues_by_severity":dict(severity),
            "issues_by_category":dict(category),
            "automated_score":round(score,1),
            "score_note":"Score heurístico limitado aos testes automatizados. UX/UI qualitativos e testes autenticados exigem revisão complementar."
        }

    def write_reports(self,payload):
        self.output.mkdir(parents=True,exist_ok=True)
        json_path=self.output/"webaudit360_report.json"
        md_path=self.output/"webaudit360_report.md"
        json_path.write_text(json.dumps(payload,ensure_ascii=False,indent=2,default=str),encoding="utf-8")

        s=payload["summary"]
        lines=[
            "# WebAudit 360 — Relatório Automatizado","",
            f"- **Site:** {self.base_url}",
            f"- **Gerado em:** {dt.datetime.now().astimezone().isoformat(timespec='seconds')}",
            f"- **Páginas analisadas:** {s['pages_analyzed']}",
            f"- **Links descobertos:** {s['links_discovered']}",
            f"- **Links quebrados/bloqueados:** {s['broken_or_blocked_links']}",
            f"- **Problemas registrados:** {s['issues_total']}",
            f"- **Score automatizado:** {s['automated_score']}/100","",
            f"> {s['score_note']}","","## Páginas",""
        ]
        for p in payload["pages"]:
            lines += [
                f"### {p['url']}",
                f"- HTTP: {p['status']}",
                f"- Tempo: {p['elapsed_ms']} ms",
                f"- Title: {p['title'] or '(ausente)'}",
                f"- H1: {', '.join(p['h1']) if p['h1'] else '(ausente)'}",
                f"- Imagens sem alt: {p['images_missing_alt']}/{p['images']}",
            ]
            if p["issues"]:
                for i in p["issues"]:
                    lines.append(f"- **{i['severity']} — {i['category']}:** {i['description']}")
            else:
                lines.append("- Nenhum alerta automatizado nesta página.")
            lines.append("")

        lines += [
            "## Limitações","",
            "- Não foram executados ataques, brute force ou exploração ativa.",
            "- UX/UI qualitativos, jornadas autenticadas e regras de negócio exigem validação humana e/ou credenciais.",
            "- Lighthouse, Core Web Vitals de campo, pentest, SAST/DAST e PDF executivo devem complementar este relatório."
        ]
        md_path.write_text("\n".join(lines),encoding="utf-8")
        print(f"[ok] JSON: {json_path}")
        print(f"[ok] Markdown: {md_path}")

    def run(self):
        print(f"WebAudit 360 — alvo autorizado: {self.base_url}")
        self.crawl()
        special=self.special_files()
        tls=self.tls_info()
        links=self.check_links()
        browser=self.browser_checks()
        payload={
            "meta":{
                "tool":"WebAudit 360",
                "version":"1.1.2",
                "base_url":self.base_url,
                "started_utc":self.started.isoformat(),
                "finished_utc":dt.datetime.now(dt.timezone.utc).isoformat(),
                "non_destructive":True
            },
            "summary":self.summary(links),
            "special_files":special,
            "tls":tls,
            "pages":[dataclasses.asdict(p) for p in self.pages],
            "links":links,
            "browser":browser
        }
        self.write_reports(payload)

def parse_args():
    ap=argparse.ArgumentParser(description="WebAudit 360 — auditoria não destrutiva de sites autorizados")
    ap.add_argument("url",help="URL do site, ex.: https://example.com")
    ap.add_argument("--max-pages",type=int,default=50,help="Máximo de páginas internas")
    ap.add_argument("--timeout",type=int,default=TIMEOUT,help="Timeout HTTP em segundos")
    ap.add_argument("--output",default="webaudit360_output",help="Diretório de saída")
    ap.add_argument("--browser",action="store_true",help="Ativa smoke tests responsivos via Playwright")
    return ap.parse_args()

def main():
    args=parse_args()
    if args.max_pages<1 or args.max_pages>1000:
        print("--max-pages deve estar entre 1 e 1000",file=sys.stderr)
        return 2
    WebAudit360(args.url,args.max_pages,args.timeout,Path(args.output),args.browser).run()
    return 0

if __name__=="__main__":
    raise SystemExit(main())