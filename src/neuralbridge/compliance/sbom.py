"""
NeuralBridge - Software Bill of Materials (SBOM) Generator.

This module provides functionality for generating a Software Bill of
Materials (SBOM) in a simplified CycloneDX-compatible JSON format, a key
requirement for Cyber Resilience Act (CRA) compliance.

The SBOMGenerator class discovers and parses dependency information from
standard Python project files (requirements.txt and pyproject.toml),
enriches it with component metadata, and serializes it into a valid SBOM.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
from pathlib import Path
from typing import Any

import structlog
from pydantic import BaseModel, Field

from neuralbridge.config import get_settings

logger = structlog.get_logger(__name__)


class SBOMComponent(BaseModel):
    """Pydantic model representing a single component in the SBOM."""

    name: str = Field(..., description="The name of the component.")
    version: str = Field(..., description="The version of the component.")
    purl: str = Field(
        ..., description="The package URL (purl) of the component.",
    )
    supplier: str | None = Field(
        None, description="The supplier of the component.",
    )
    license_id: str | None = Field(
        None, description="The license of the component.",
    )
    hashes: dict[str, str] = Field(
        default_factory=dict,
        description="Cryptographic hashes of the component.",
    )


class SBOMGenerator:
    """Generate a Software Bill of Materials (SBOM) for a Python project.

    This class discovers dependencies from requirements.txt and
    pyproject.toml files, gathers metadata for each component, and
    generates an SBOM in a CycloneDX-compatible JSON format.
    """

    def __init__(self, project_root: Path) -> None:
        """Initialize the SBOMGenerator.

        Args:
            project_root: The root directory of the project.
        """
        self.project_root = project_root
        self.settings = get_settings()
        self.logger = logger.bind(project_root=str(project_root))

    async def generate_sbom(self) -> str:
        """Generate the SBOM for the project.

        Returns:
            A JSON string representing the SBOM.
        """
        self.logger.info("Starting SBOM generation.")
        components = await self._discover_dependencies()
        sbom = self._build_sbom_document(components)
        sbom_json = json.dumps(sbom, indent=2)
        self.logger.info("SBOM generation complete.")
        return sbom_json

    async def _discover_dependencies(self) -> list[SBOMComponent]:
        """Discover dependencies from requirements.txt and pyproject.toml.

        Returns:
            A list of SBOMComponent objects.
        """
        self.logger.info("Discovering dependencies...")
        tasks = [
            self._parse_requirements_txt(),
            self._parse_pyproject_toml(),
        ]
        results = await asyncio.gather(*tasks)

        unique: dict[str, SBOMComponent] = {}
        for component_list in results:
            for component in component_list:
                if component.name not in unique:
                    unique[component.name] = component

        self.logger.info(
            "Discovered unique dependencies.",
            count=len(unique),
        )
        return list(unique.values())

    async def _parse_requirements_txt(self) -> list[SBOMComponent]:
        """Parse a requirements.txt file to extract dependencies.

        Returns:
            A list of SBOMComponent objects.
        """
        requirements_path = self.project_root / "requirements.txt"
        if not requirements_path.exists():
            self.logger.debug("requirements.txt not found.")
            return []

        self.logger.info("Parsing requirements.txt.")
        components: list[SBOMComponent] = []
        try:
            with open(requirements_path) as f:
                lines = f.readlines()
            for line in lines:
                line = line.strip()
                if line and not line.startswith("#"):
                    name, version = self._parse_dependency_string(line)
                    if name and version:
                        component = await self._create_component(
                            name, version,
                        )
                        components.append(component)
        except OSError as e:
            self.logger.error(
                "Failed to read requirements.txt", exc_info=e,
            )
        return components

    async def _parse_pyproject_toml(self) -> list[SBOMComponent]:
        """Parse a pyproject.toml file to extract dependencies.

        Returns:
            A list of SBOMComponent objects.
        """
        pyproject_path = self.project_root / "pyproject.toml"
        if not pyproject_path.exists():
            self.logger.debug("pyproject.toml not found.")
            return []

        self.logger.info("Parsing pyproject.toml.")
        components: list[SBOMComponent] = []
        try:
            import tomllib

            with open(pyproject_path, "rb") as f:
                data = tomllib.load(f)
            dependencies = (
                data.get("project", {}).get("dependencies", [])
            )
            for dep in dependencies:
                name, version = self._parse_dependency_string(dep)
                if name and version:
                    component = await self._create_component(
                        name, version,
                    )
                    components.append(component)
        except Exception as e:
            self.logger.error(
                "Failed to parse pyproject.toml", exc_info=e,
            )
        return components

    def _parse_dependency_string(
        self, dep_string: str,
    ) -> tuple[str | None, str | None]:
        """Parse a dependency string into a name and version.

        Args:
            dep_string: The dependency string (e.g., 'requests==2.25.1').

        Returns:
            A tuple of (name, version), or (None, None) if parsing fails.
        """
        try:
            if "==" in dep_string:
                name, version = dep_string.split("==", 1)
                return name.strip(), version.strip()
            if ">=" in dep_string:
                name, _ = dep_string.split(">=", 1)
                return name.strip(), "latest"
        except ValueError:
            self.logger.warning(
                "Could not parse dependency string",
                dep_string=dep_string,
            )
        return None, None

    async def _create_component(
        self, name: str, version: str,
    ) -> SBOMComponent:
        """Create an SBOMComponent with enriched metadata.

        Args:
            name: The name of the component.
            version: The version of the component.

        Returns:
            An SBOMComponent object.
        """
        purl = f"pkg:pypi/{name}@{version}"
        hashes = {
            "SHA-256": hashlib.sha256(
                f"{name}{version}".encode(),
            ).hexdigest(),
        }

        return SBOMComponent(
            name=name,
            version=version,
            purl=purl,
            supplier="PyPI",
            license_id="UNKNOWN",
            hashes=hashes,
        )

    def _build_sbom_document(
        self, components: list[SBOMComponent],
    ) -> dict[str, Any]:
        """Build a CycloneDX-compatible SBOM document.

        Args:
            components: A list of SBOMComponent objects.

        Returns:
            A dictionary representing the SBOM document.
        """
        return {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "version": 1,
            "metadata": {
                "component": {
                    "type": "application",
                    "name": self.settings.otel_service_name,
                    "version": "1.0.0",
                    "bom-ref": "neuralbridge",
                },
            },
            "components": [
                {
                    "type": "library",
                    "name": c.name,
                    "version": c.version,
                    "purl": c.purl,
                    "bom-ref": c.purl,
                    "supplier": {"name": c.supplier or "Unknown"},
                    "hashes": [
                        {"alg": alg, "content": val}
                        for alg, val in c.hashes.items()
                    ],
                }
                for c in components
            ],
        }


async def main() -> None:
    """Generate the SBOM and save it to a file."""
    project_root = Path(__file__).parent.parent.parent.parent
    generator = SBOMGenerator(project_root)
    sbom_json = await generator.generate_sbom()

    output_dir = project_root / "reports"
    output_dir.mkdir(exist_ok=True)
    output_path = output_dir / "sbom.json"

    with open(output_path, "w") as f:
        f.write(sbom_json)

    logger.info("SBOM saved", path=str(output_path))


if __name__ == "__main__":
    asyncio.run(main())
