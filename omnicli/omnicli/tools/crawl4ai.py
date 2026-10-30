"""
Crawl4AI web crawler tool for OmniCLI agents.

Integrates Crawl4AI for high-performance web crawling with clean Markdown
extraction optimized for LLM processing.

Modeled after OpenManus's Crawl4aiTool.
"""

from __future__ import annotations

import asyncio
from typing import Any, List, Union
from urllib.parse import urlparse

from omnicli.base_tool import BaseTool, ToolResult


class Crawl4aiTool(BaseTool):
    """Web crawler tool powered by Crawl4AI.

    Provides clean markdown extraction optimized for AI agents.
    Handles JavaScript-heavy sites and dynamic content.
    """

    name: str = "crawl4ai"
    description: str = (
        "Web crawler that extracts clean, AI-ready content from web pages. "
        "Features: extracts clean markdown content optimized for LLMs, "
        "handles JavaScript-heavy sites and dynamic content, supports multiple "
        "URLs in a single request, fast and reliable with built-in error handling."
    )
    parameters: dict = {
        "type": "object",
        "properties": {
            "urls": {
                "type": "array",
                "items": {"type": "string"},
                "description": "List of URLs to crawl. Can be a single URL or multiple URLs.",
                "minItems": 1,
            },
            "timeout": {
                "type": "integer",
                "description": "Timeout in seconds for each URL. Default is 30.",
                "default": 30,
                "minimum": 5,
                "maximum": 120,
            },
            "bypass_cache": {
                "type": "boolean",
                "description": "Whether to bypass cache and fetch fresh content. Default is false.",
                "default": False,
            },
            "word_count_threshold": {
                "type": "integer",
                "description": "Minimum word count for content blocks. Default is 10.",
                "default": 10,
                "minimum": 1,
            },
        },
        "required": ["urls"],
    }

    async def execute(
        self,
        urls: Union[str, List[str]],
        timeout: int = 30,
        bypass_cache: bool = False,
        word_count_threshold: int = 10,
        **kwargs: Any,
    ) -> ToolResult:
        """Execute web crawling for the specified URLs."""
        if isinstance(urls, str):
            url_list = [urls]
        else:
            url_list = urls

        valid_urls = []
        for url in url_list:
            if self._is_valid_url(url):
                valid_urls.append(url)

        if not valid_urls:
            return ToolResult(error="No valid URLs provided")

        try:
            from crawl4ai import (
                AsyncWebCrawler,
                BrowserConfig,
                CacheMode,
                CrawlerRunConfig,
            )

            browser_config = BrowserConfig(
                headless=True,
                verbose=False,
                browser_type="chromium",
                ignore_https_errors=True,
                java_script_enabled=True,
            )

            run_config = CrawlerRunConfig(
                cache_mode=CacheMode.BYPASS if bypass_cache else CacheMode.ENABLED,
                word_count_threshold=word_count_threshold,
                process_iframes=True,
                remove_overlay_elements=True,
                excluded_tags=["script", "style"],
                page_timeout=timeout * 1000,
                wait_until="domcontentloaded",
            )

            results = []
            successful_count = 0
            failed_count = 0

            async with AsyncWebCrawler(config=browser_config) as crawler:
                for url in valid_urls:
                    try:
                        result = await crawler.arun(url=url, config=run_config)

                        if result.success:
                            markdown = result.markdown or ""
                            word_count = len(markdown.split())

                            links_count = 0
                            if hasattr(result, "links") and result.links:
                                links_count = (
                                    len(result.links.get("internal", []))
                                    + len(result.links.get("external", []))
                                )

                            images_count = 0
                            if hasattr(result, "media") and result.media:
                                images_count = len(result.media.get("images", []))

                            results.append(
                                {
                                    "url": url,
                                    "success": True,
                                    "status_code": getattr(result, "status_code", 200),
                                    "title": result.metadata.get("title")
                                    if result.metadata
                                    else None,
                                    "markdown": markdown,
                                    "word_count": word_count,
                                    "links_count": links_count,
                                    "images_count": images_count,
                                }
                            )
                            successful_count += 1
                        else:
                            results.append(
                                {
                                    "url": url,
                                    "success": False,
                                    "error_message": getattr(
                                        result, "error_message", "Unknown error"
                                    ),
                                }
                            )
                            failed_count += 1

                    except Exception as exc:  # noqa: BLE001
                        results.append(
                            {
                                "url": url,
                                "success": False,
                                "error_message": str(exc),
                            }
                        )
                        failed_count += 1

            # Format output
            output_lines = ["🕷️ Crawl4AI Results Summary:"]
            output_lines.append(f"📊 Total URLs: {len(valid_urls)}")
            output_lines.append(f"✅ Successful: {successful_count}")
            output_lines.append(f"❌ Failed: {failed_count}")
            output_lines.append("")

            for i, result in enumerate(results, 1):
                output_lines.append(f"{i}. {result['url']}")
                if result["success"]:
                    output_lines.append(
                        f"   ✅ Status: Success (HTTP {result.get('status_code', 'N/A')})"
                    )
                    if result.get("title"):
                        output_lines.append(f"   📄 Title: {result['title']}")
                    if result.get("markdown"):
                        content_preview = result["markdown"]
                        if len(content_preview) > 300:
                            content_preview = content_preview[:300] + "..."
                        output_lines.append(f"   📝 Content: {content_preview}")
                    output_lines.append(
                        f"   📊 Stats: {result.get('word_count', 0)} words, "
                        f"{result.get('links_count', 0)} links, "
                        f"{result.get('images_count', 0)} images"
                    )
                else:
                    output_lines.append(f"   ❌ Status: Failed")
                    if result.get("error_message"):
                        output_lines.append(f"   🚫 Error: {result['error_message']}")
                output_lines.append("")

            return ToolResult(output="\n".join(output_lines))

        except ImportError:
            return ToolResult(
                error="Crawl4AI is not installed. Install with: pip install crawl4ai"
            )
        except Exception as exc:  # noqa: BLE001
            return ToolResult(error=f"Crawl4AI execution failed: {exc}")

    def _is_valid_url(self, url: str) -> bool:
        """Validate if a URL is properly formatted."""
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc]) and result.scheme in [
                "http",
                "https",
            ]
        except Exception:
            return False