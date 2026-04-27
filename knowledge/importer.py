"""
knowledge/importer.py — Universal Security Dataset Importer

Can parse CSV, JSON, and JSONL exploit datasets and feed them into the 
AgentLearning table. Includes AI-assisted "distillation" for messy data.
"""
from __future__ import annotations

import json
import csv
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime
import asyncio

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn

from core.database import get_session, init_db, run_sync
from core.models import AgentLearning
from agents.llm.ollama_client import OllamaClient
from core.config import get_config

console = Console()

class ExploitImporter:
    def __init__(self):
        self.config = get_config()
        self.llm = OllamaClient(
            host=self.config.ollama.host,
            model=self.config.ollama.model
        )

    def run(self, file_path: str, use_ai_cleaning: bool = False):
        """Entry point for the import process."""
        path = Path(file_path)
        if not path.exists():
            console.print(f"[red]Error: File {file_path} not found.[/red]")
            return

        console.print(f"[cyan]Importing dataset from {path.name}...[/cyan]")
        
        data = self._load_file(path)
        if not data:
            console.print("[red]No records found in file.[/red]")
            params = []
        else:
            asyncio.run(self._process_records(data, use_ai_cleaning))

    def _load_file(self, path: Path) -> List[Dict]:
        """Detect format and load records. Supports JSON, JSONL, CSV, and Directories."""
        if path.is_dir():
            return self._load_directory(path)

        suffix = path.suffix.lower()
        records = []

        try:
            if suffix == ".json":
                with open(path, "r", encoding="utf-8") as f:
                    content = json.load(f)
                    records = content if isinstance(content, list) else [content]
            elif suffix == ".jsonl":
                with open(path, "r", encoding="utf-8") as f:
                    for line in f:
                        if line.strip():
                            records.append(json.loads(line))
            elif suffix == ".csv":
                with open(path, "r", encoding="utf-8") as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        records.append(row)
        except Exception as e:
            console.print(f"[red]Failed to parse {path.name}: {e}[/red]")
            
        return records

    def _load_directory(self, path: Path) -> List[Dict]:
        """Walk a directory and treat files as vulnerability snippets."""
        records = []
        for file in path.rglob("*"):
            if file.is_file() and not file.name.startswith("."):
                try:
                    # Use the parent directory name as the category/context
                    category = file.parent.name
                    with open(file, "r", encoding="utf-8") as f:
                        content = f.read()
                    
                    records.append({
                        "description": f"Vulnerable example of {category} (file: {file.name})",
                        "exploit": content
                    })
                except Exception:
                    continue
        return records

    async def _process_records(self, records: List[Dict], use_ai_cleaning: bool):
        """Process and save records to database."""
        await init_db()
        
        count = 0
        skipped = 0

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("Importing...", total=len(records))

            for rec in records:
                try:
                    # Generic mapping logic (look for common security dataset columns)
                    # Priority: desc/description/text, exploit/code/snippet
                    context = (
                        rec.get("input") or rec.get("description") or 
                        rec.get("desc") or rec.get("text") or rec.get("title") or ""
                    )
                    outcome = (
                        rec.get("output") or rec.get("exploit") or 
                        rec.get("code") or rec.get("snippet") or rec.get("proof") or ""
                    )

                    if not context and not outcome:
                        skipped += 1
                        progress.advance(task)
                        continue

                    # AI-Assisted Cleaning
                    if use_ai_cleaning and context:
                        clean_data = await self._clean_with_ai(context, outcome)
                        context = clean_data.get("pattern", context)
                        outcome = clean_data.get("logic", outcome)

                    # Save to DB
                    async with get_session() as session:
                        learning = AgentLearning(
                            pattern_context=str(context)[:2000],
                            outcome_notes=str(outcome)[:5000],
                            is_false_positive=0
                        )
                        session.add(learning)
                        await session.commit()
                    
                    count += 1
                except Exception as e:
                    console.print(f"[dim]Record skip: {e}[/dim]")
                    skipped += 1
                
                progress.advance(task)

        console.print(f"\n[green]✓ Successfully imported {count} learning entries.[/green]")
        if skipped:
            console.print(f"[yellow]⚠ Skipped {skipped} records (missing data or errors).[/yellow]")

    async def _clean_with_ai(self, raw_context: str, raw_outcome: str) -> Dict[str, str]:
        """Convert messy exploit data into clean logic patterns."""
        prompt = f"""
I am importing an exploit dataset into an AI security scanner. The data is messy.
Please "distill" this into a clean pattern for the AI to learn from.

RAW DESCRIPTION:
{raw_context[:1000]}

RAW EXPLOIT/CODE:
{raw_outcome[:2000]}

Respond ONLY with valid JSON in this format:
{{
  "pattern": "A clean, technical description of the vulnerability pattern (e.g. 'SQL injection via unsanitized ID parameter in GET request')",
  "logic": "The core exploit logic or payload template (e.g. '1' OR '1'='1')"
}}
"""
        try:
            # Use blocking chat inside the async runner (or use a real async generator if available)
            response = ""
            for chunk in self.llm.chat([{"role": "user", "content": prompt}]):
                response += chunk
            
            data = self.llm.validate_json(response)
            if data:
                return data
        except Exception:
            pass
        
        return {"pattern": raw_context, "logic": raw_outcome}
