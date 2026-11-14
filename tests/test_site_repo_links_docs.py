"""``stripRepoLinks`` removes every spelling of a link into the (private) repository, and no
on-site doc keeps one while ``NEXT_PUBLIC_REPO_PUBLIC`` is off.

The functions under test are run by Node (``--experimental-strip-types``) exactly as the site's
own modules are, in the style of ``tests/test_site_capabilities_contract.py``.
"""

from __future__ import annotations

import json

import pytest

from .test_site_honesty import _node

NEEDLE = "github.com/iceccarelli"
URL = "https://github.com/iceccarelli/neuralbridge"


@pytest.fixture(autouse=True)
def _flag_off(monkeypatch):
    monkeypatch.delenv("NEXT_PUBLIC_REPO_PUBLIC", raising=False)


def strip(*samples: str) -> list[str]:
    script = ("const m = await import('./app/lib/links.ts');"
              f"const xs = {json.dumps(list(samples))};"
              "process.stdout.write(JSON.stringify(xs.map((x) => m.stripRepoLinks(x))));")
    out = _node(script, stub_marked=True)
    assert isinstance(out, list)
    return out


CASES = {
    "inline": (f"See [the source]({URL}) now.", "See the source now."),
    "inline_blob": (f"[ADR]({URL}/blob/main/deploy/x.md#a) ok", "ADR ok"),
    "inline_double_title": (f'[t]({URL} "The repo") end', "t end"),
    "inline_single_title": (f"[t]({URL} 'The repo') end", "t end"),
    "inline_paren_title": (f"[t]({URL} (The repo)) end", "t end"),
    "inline_angle": (f"[t](<{URL}> \"x\") end", "t end"),
    "inline_profile": ("[me](https://github.com/iceccarelli) end", "me end"),
    "image": (f"![logo]({URL}/raw/main/a.png) end", "logo end"),
    "autolink": (f"Source: <{URL}>. Thanks", "Source:. Thanks"),
    "bare": (f"Source at {URL}/issues for details", "Source at for details"),
    "bare_in_parens": (f"(see {URL})", "(see)"),
    "bare_no_scheme": ("see github.com/iceccarelli/neuralbridge for details", "see for details"),
    "bare_in_backticks": (f"run `pip install git+{URL}.git` now", "run `pip install` now"),
    "code_span_only_url": (f"clone `{URL}` today", "clone today"),
    "ssh": ("git@github.com:iceccarelli/neuralbridge.git", ""),
    "upper_case": ("[t](HTTPS://GitHub.com/iceccarelli/NeuralBridge) end", "t end"),
    "clone": (f"```sh\ngit clone {URL}.git\ncd neuralbridge\n```",
              "```sh\n# get a copy of the source from NeuralBridge (see the Contact page)\n"
              "cd neuralbridge\n```"),
    "reference_full": (f"Read [the repo][r1] first.\n\n[r1]: {URL}\n", "Read the repo first.\n\n"),
    "reference_titled": (f'Read [the repo][R1].\n\n[r1]: <{URL}> "Repo"\n', "Read the repo.\n\n"),
    "reference_collapsed": (f"Read [repo][].\n\n[repo]: {URL}\n", "Read repo.\n\n"),
    "reference_shortcut": (f"Read [repo] first.\n\n[repo]: {URL}/issues\n", "Read repo first.\n\n"),
    "reference_multiword": (f"A [source code] b.\n\n[Source  Code]: {URL}\n", "A source code b.\n\n"),
}


@pytest.mark.parametrize("name", CASES)
def test_each_link_form_is_stripped_and_the_words_are_kept(name):
    given, expected = CASES[name]
    (out,) = strip(given)
    assert NEEDLE not in out.lower() and "git@github" not in out.lower(), out
    assert out == expected


def test_links_elsewhere_and_other_references_are_untouched():
    other = ("[docs](https://neuralbridge.io/docs \"Docs\") and [x][y] and <https://example.org>\n"
             "\n[y]: https://example.org/y\n[z]: https://github.com/someoneelse/repo\n"
             "[other](https://github.com/someoneelse/repo)\n")
    (out,) = strip(other)
    assert out == other


def test_a_reference_to_an_unrelated_definition_is_kept_when_another_one_is_stripped():
    given = f"[a][keep] and [b][drop]\n\n[keep]: https://example.org\n[drop]: {URL}\n"
    (out,) = strip(given)
    assert out == "[a][keep] and b\n\n[keep]: https://example.org\n"


def test_stripping_is_idempotent_and_the_checker_would_notice_a_leftover():
    given = f"[t]({URL} \"x\") <{URL}> {URL}\n[r]: {URL}\n"
    (once,) = strip(given)
    (twice,) = strip(once)
    assert once == twice and NEEDLE not in once
    assert NEEDLE in given        # the input did carry it: the assertion above can fail


# ------------------------------------------------------------------ every on-site doc
def test_no_on_site_doc_keeps_a_repository_url_with_the_flag_off():
    out = _node("""
      import fs from 'node:fs';
      const m = await import('./app/lib/docs.ts');
      const files = new Set(['ROADMAP.md', 'SECURITY.md']);
      for (const { slug } of m.listDocSlugs()) files.add(m.loadDoc(slug).editPath);
      const left = [];
      for (const f of [...files].sort()) {
        if (!fs.existsSync(f)) continue;
        const raw = fs.readFileSync(f, 'utf-8');
        const shown = m.rewriteLinks(raw);
        if (/github\\.com[/:]iceccarelli/i.test(shown)) left.push(f);
      }
      process.stdout.write(JSON.stringify({ files: [...files].sort(), left }));
    """, stub_marked=True)
    assert "docs/getting-started.md" in out["files"]
    assert any(f.startswith("deploy/assurance/") for f in out["files"])
    assert out["left"] == [], f"on-site docs still link into the repository: {out['left']}"


def test_getting_started_clone_line_is_replaced():
    out = _node("""
      import fs from 'node:fs';
      const m = await import('./app/lib/docs.ts');
      process.stdout.write(JSON.stringify(m.rewriteLinks(fs.readFileSync('docs/getting-started.md', 'utf-8'))));
    """, stub_marked=True)
    assert "git clone" not in out or "get a copy of the source from NeuralBridge" in out
    assert NEEDLE not in out


def test_with_the_flag_on_the_links_are_left_alone(monkeypatch):
    monkeypatch.setenv("NEXT_PUBLIC_REPO_PUBLIC", "true")
    out = _node("""
      const m = await import('./app/lib/docs.ts');
      process.stdout.write(JSON.stringify(m.rewriteLinks('[t](https://github.com/iceccarelli/neuralbridge)')));
    """, stub_marked=True)
    assert out == "[t](https://github.com/iceccarelli/neuralbridge)"


# ------------------------------------------------------------------ package and docs metadata
def test_package_metadata_advertises_no_private_repository():
    import tomllib
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    urls = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))["project"]["urls"]
    assert urls == {"Homepage": "https://neuralbridge.io",
                    "Documentation": "https://neuralbridge.io/docs"}
    assert not any("github" in v.lower() for v in urls.values())


def test_mkdocs_config_names_no_repository_or_edit_link():
    from pathlib import Path
    import yaml

    text = (Path(__file__).resolve().parents[1] / "mkdocs.yml").read_text(encoding="utf-8")
    config = yaml.safe_load(text)
    for key in ("repo_url", "repo_name", "edit_uri"):
        assert key not in config
    assert "github.com/iceccarelli" not in text
    assert "visuals/VISUAL_ARCHITECTURE.md" in config["exclude_docs"].splitlines()


def test_the_getting_started_notebook_does_not_call_the_product_open_source():
    from pathlib import Path

    text = (Path(__file__).resolve().parents[1] / "notebooks"
            / "01_getting_started.ipynb").read_text(encoding="utf-8")
    assert "open-source" not in text.lower() and "open source" not in text.lower()
