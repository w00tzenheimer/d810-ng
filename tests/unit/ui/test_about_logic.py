"""Pure-logic tests for the About dialog model (ticket d81-zijs).

``about_logic`` must stay IDA-free and Qt-free so the About content is testable
without a decompiler: the dialog on top is a thin renderer.
"""

from __future__ import annotations

import pytest

from d810.ui.about_logic import (
    ACKNOWLEDGEMENTS,
    AUTHORS,
    HELP_URL,
    ISSUES_URL,
    PRODUCT_NAME,
    REPOSITORY_URL,
    UNKNOWN_VERSION,
    AboutModel,
    about_model,
    render_html,
    render_plain,
)


class TestAboutModel:
    def test_reports_the_package_version(self) -> None:
        import d810

        model = about_model()
        assert model.version == d810.__version__
        assert model.product == PRODUCT_NAME

    def test_product_name_uses_the_user_facing_spelling(self) -> None:
        """Labels say d810-ng; only ACTION_IDs use the d810ng form."""
        assert PRODUCT_NAME == "d810-ng"

    def test_links_are_ordered_version_repo_issues_help(self) -> None:
        model = about_model()
        assert [label for label, _ in model.links] == [
            "Repository",
            "Issues",
            "Help",
        ]
        assert [url for _, url in model.links] == [
            REPOSITORY_URL,
            ISSUES_URL,
            HELP_URL,
        ]

    @pytest.mark.parametrize(
        "url", [REPOSITORY_URL, ISSUES_URL, HELP_URL]
    )
    def test_urls_are_absolute_https_on_the_project_repo(self, url: str) -> None:
        assert url.startswith("https://github.com/w00tzenheimer/d810-ng")

    def test_issues_and_help_are_distinct_targets(self) -> None:
        assert ISSUES_URL != HELP_URL != REPOSITORY_URL


class TestVersionFallback:
    """A missing version must degrade, never raise into a Qt slot.

    Mirrors lpccp-8c87: a malformed project raised out of `_load_config` and
    took the whole panel down. An About box has even less business raising.
    """

    def test_missing_version_attribute_yields_unknown(self, monkeypatch) -> None:
        import d810

        monkeypatch.delattr(d810, "__version__", raising=False)
        assert about_model().version == UNKNOWN_VERSION

    def test_blank_version_yields_unknown(self, monkeypatch) -> None:
        import d810

        monkeypatch.setattr(d810, "__version__", "   ", raising=False)
        assert about_model().version == UNKNOWN_VERSION

    def test_non_string_version_yields_unknown(self, monkeypatch) -> None:
        import d810

        monkeypatch.setattr(d810, "__version__", object(), raising=False)
        assert about_model().version == UNKNOWN_VERSION


class TestRendering:
    def test_title_line_names_product_and_version(self) -> None:
        model = about_model()
        assert model.title == f"About {PRODUCT_NAME}"

    def test_model_is_immutable(self) -> None:
        model = about_model()
        with pytest.raises((AttributeError, TypeError)):
            model.version = "9.9.9"  # type: ignore[misc]

    def test_is_a_dataclass_instance(self) -> None:
        assert isinstance(about_model(), AboutModel)


class TestAuthors:
    def test_both_authors_are_listed_in_order(self) -> None:
        assert about_model().authors == AUTHORS
        assert [name for name, _ in AUTHORS] == ["w00tzenheimer", "mahmoudimus"]

    @pytest.mark.parametrize("name,url", AUTHORS)
    def test_each_author_links_to_their_github_profile(
        self, name: str, url: str
    ) -> None:
        assert url == f"https://github.com/{name}"

    def test_every_author_carries_a_name_and_a_url(self) -> None:
        for name, url in about_model().authors:
            assert name and url


class TestAcknowledgements:
    def test_model_carries_every_entry(self) -> None:
        assert about_model().acknowledgements == ACKNOWLEDGEMENTS
        assert len(ACKNOWLEDGEMENTS) == 3

    def test_credits_the_people_named_in_the_readme(self) -> None:
        joined = " ".join(ACKNOWLEDGEMENTS)
        for person in ("Rolf Rolles", "Dennis Elser", "Boris Batteux"):
            assert person in joined

    def test_carries_the_readme_project_links(self) -> None:
        joined = " ".join(ACKNOWLEDGEMENTS)
        for url in (
            "https://github.com/RolfRolles/HexRaysDeob",
            "https://github.com/patois/genmc",
            "https://gitlab.com/borisbatteux",
        ):
            assert url in joined

    def test_entries_render_without_markdown_syntax_leaking(self) -> None:
        for entry in about_model().acknowledgements:
            assert "](" not in render_plain(entry)


class TestMarkdownRenderers:
    """One source of truth for the prose; two derived display forms."""

    def test_plain_keeps_anchor_text_and_drops_the_url(self) -> None:
        assert render_plain("see [docs](https://example.com/x) now") == (
            "see docs now"
        )

    def test_html_emits_an_anchor(self) -> None:
        assert render_html("see [docs](https://example.com/x)") == (
            'see <a href="https://example.com/x">docs</a>'
        )

    def test_text_without_links_is_unchanged(self) -> None:
        assert render_plain("no links here") == "no links here"
        assert render_html("no links here") == "no links here"

    def test_html_escapes_surrounding_markup(self) -> None:
        assert render_html("a < b & c") == "a &lt; b &amp; c"

    def test_html_escapes_inside_anchor_text(self) -> None:
        assert render_html("[a<b](https://e.com)") == (
            '<a href="https://e.com">a&lt;b</a>'
        )

    @pytest.mark.parametrize("entry", ACKNOWLEDGEMENTS)
    def test_every_acknowledgement_round_trips(self, entry: str) -> None:
        assert "](" not in render_plain(entry)
        html = render_html(entry)
        assert "](" not in html
        assert html.count("<a href=") == entry.count("](")
