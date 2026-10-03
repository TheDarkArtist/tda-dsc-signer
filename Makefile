# make install            -> venv (with system gi, dependencies from uv.lock with hashes) + command links + desktop entry
# Every location is overridable, e.g. for a dry run:
#   make install TDA_DATA=/x/share/tda-dsc-signer TDA_BIN=/x/bin TDA_APPS=/x/apps TDA_ICONS=/x/icons TDA_META=/x/metainfo
# (DATA / BIN / APPS / ICONS are accepted as older aliases.)
TDA_DATA  ?= $(or $(DATA),$(HOME)/.local/share/tda-dsc-signer)
TDA_BIN   ?= $(or $(BIN),$(HOME)/.local/bin)
TDA_APPS  ?= $(or $(APPS),$(HOME)/.local/share/applications)
TDA_ICONS ?= $(or $(ICONS),$(HOME)/.local/share/icons/hicolor/scalable/apps)
TDA_META  ?= $(or $(META),$(HOME)/.local/share/metainfo)
APPID = in.tdacorp.DscSigner
PY = $(TDA_DATA)/venv/bin/python

.PHONY: install uninstall
install:
	@# the desktop entry gets the ABSOLUTE command path (a graphical session's PATH usually lacks ~/.local/bin); refuse anything
	@# that would need Desktop Entry escaping rather than risk a broken Exec line
	@case "$(TDA_BIN)" in /*) ;; *) echo "TDA_BIN must be an absolute path: $(TDA_BIN)" >&2; exit 1;; esac
	@case "$(TDA_BIN)" in *[[:space:]\"\\$$\`%\&\|\;]*) echo "TDA_BIN contains a space or one of \" \\ $$ \` % & | ; which the desktop entry's Exec line cannot carry safely: $(TDA_BIN)" >&2; exit 1;; esac
	uv venv --system-site-packages --python /usr/bin/python3 --allow-existing $(TDA_DATA)/venv
	# dependencies exactly as locked (uv.lock, SHA-256 verified), then the project itself without resolving anything
	uv export --frozen --no-dev --no-emit-project --format requirements-txt | uv pip install --python $(PY) --require-hashes -r -
	uv pip install --python $(PY) --no-deps --reinstall-package tda-dsc-signer .
	mkdir -p $(TDA_BIN)
	ln -sf $(TDA_DATA)/venv/bin/tda-dsc-signer $(TDA_BIN)/tda-dsc-signer
	sed 's|^Exec=.*|Exec=$(TDA_BIN)/tda-dsc-signer %f|' data/$(APPID).desktop | install -Dm644 /dev/stdin $(TDA_APPS)/$(APPID).desktop
	install -Dm644 data/$(APPID).svg $(TDA_ICONS)/$(APPID).svg
	install -Dm644 data/$(APPID).metainfo.xml $(TDA_META)/$(APPID).metainfo.xml
	@# best-effort cache refresh, only inside the icon theme root of TDA_ICONS and TDA_APPS; never fails the install
	-@r="$(abspath $(TDA_ICONS)/../..)"; case "$$r" in */hicolor) command -v gtk-update-icon-cache >/dev/null 2>&1 && gtk-update-icon-cache -f -t "$$r" >/dev/null 2>&1;; esac; true
	-@command -v update-desktop-database >/dev/null 2>&1 && update-desktop-database "$(TDA_APPS)" >/dev/null 2>&1 || true
	@echo "installed: $(TDA_BIN)/tda-dsc-signer  (the short alias 'dsc-sign' is in the venv: $(TDA_DATA)/venv/bin/dsc-sign)"

uninstall:
	rm -rf "$(TDA_DATA)/venv"
	rm -f "$(TDA_BIN)/tda-dsc-signer" "$(TDA_APPS)/$(APPID).desktop" "$(TDA_ICONS)/$(APPID).svg" "$(TDA_META)/$(APPID).metainfo.xml"

# make release VERSION=X.Y.Z  -> bump files, check consistency, run tests + lint, then PRINT the git commands. Never commits, tags or pushes.
.PHONY: release
release:
	@test -n "$(VERSION)" || { echo "usage: make release VERSION=X.Y.Z" >&2; exit 1; }
	python3 scripts/bump-version.py $(VERSION)
	python3 scripts/check-release.py --tag v$(VERSION)
	uv run pytest -q --ignore=tests/smoke_gui.py
	uv run ruff check
	uv run ruff format --check
	@echo
	@echo "Release v$(VERSION) is prepared. Review 'git diff', then run:"
	@echo '  git commit -am "chore(release): v$(VERSION)"'
	@echo '  git tag -a v$(VERSION) -m "v$(VERSION)"'
	@echo '  git push --follow-tags'
