# eagle.py
#
# Copyright 2026 mirkobrombin <brombin94@gmail.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, in version 3 of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import os
import time
import shutil
import uuid
from glob import glob
from .runtime import patoolib
from gettext import gettext as _

from .runtime import Paths, BottleConfig, Result, SignalManager, Signals, Logger, Gio, APP_ID, run_tool, Cancelled, check_cancelled
from .intel import EagleIntel

logging = Logger()

STEP_DELAY = 0.12 # to allow seeing the analysis progress


class EagleManager:
    """Windows executable analysis with native PE and YARA scanners."""

    VS_PRODUCTS = {
        0x0104: "VS 2017", 0x0105: "VS 2017", 0x0106: "VS 2017",
        0x010A: "VS 2019", 0x010B: "VS 2019", 0x010C: "VS 2019",
        0x010D: "VS 2019", 0x010E: "VS 2019", 0x010F: "VS 2019",
        0x0114: "VS 2022", 0x0115: "VS 2022", 0x0116: "VS 2022",
        0x0117: "VS 2022", 0x0118: "VS 2022", 0x0119: "VS 2022",
        0x00FF: "VS 2015", 0x00EB: "VS 2013", 0x00D9: "VS 2012",
        0x00C7: "VS 2010", 0x0083: "VS 2008", 0x006D: "VS 2005",
    }

    DLL_MAPPINGS = {
        "d3d8.dll": ("DirectX 8", "Graphics"), "d3d9.dll": ("DirectX 9", "Graphics"),
        "d3d10.dll": ("DirectX 10", "Graphics"), "d3d11.dll": ("DirectX 11", "Graphics"),
        "d3d12.dll": ("DirectX 12", "Graphics"), "dxgi.dll": ("DXGI", "Graphics"),
        "d3dcompiler_47.dll": ("D3D Compiler", "Graphics"),
        "opengl32.dll": ("OpenGL", "Graphics"), "vulkan-1.dll": ("Vulkan", "Graphics"),
        "nvapi.dll": ("NVAPI", "Graphics"), "nvapi64.dll": ("NVAPI", "Graphics"),
        "amd_ags_x64.dll": ("AMD AGS", "Graphics"),
        "physx_loader.dll": ("PhysX", "Graphics"), "physx3_x64.dll": ("PhysX", "Graphics"),
        "d3dx9_43.dll": ("D3DX9", "Graphics"), "d3dx11_43.dll": ("D3DX11", "Graphics"),
        "nvngx_dlss.dll": ("DLSS", "Upscaling"), "nvngx_dlssg.dll": ("DLSS 3 Frame Gen", "Upscaling"),
        "libxess.dll": ("Intel XeSS", "Upscaling"),
        "ffx_fsr2_api_x64.dll": ("AMD FSR 2", "Upscaling"), "amd_fidelityfx_dx12.dll": ("AMD FSR", "Upscaling"),
        "amd_fidelityfx_vk.dll": ("AMD FSR", "Upscaling"),
        "xaudio2_7.dll": ("XAudio 2.7", "Audio"), "xaudio2_9.dll": ("XAudio 2.9", "Audio"),
        "x3daudio1_7.dll": ("X3DAudio", "Audio"),
        "fmod.dll": ("FMOD", "Audio"), "fmod64.dll": ("FMOD", "Audio"),
        "fmodstudio.dll": ("FMOD Studio", "Audio"),
        "wwise.dll": ("Wwise", "Audio"),
        "binkw32.dll": ("Bink", "Audio"), "binkw64.dll": ("Bink", "Audio"),
        "openal32.dll": ("OpenAL", "Audio"), "dsound.dll": ("DirectSound", "Audio"),
        "miles32.dll": ("Miles", "Audio"), "mss32.dll": ("Miles", "Audio"),
        "mscoree.dll": (".NET Framework", "Runtimes"),
        "clr.dll": (".NET CLR", "Runtimes"),
        "hostfxr.dll": (".NET Core/5+", "Runtimes"),
        "coreclr.dll": (".NET Core CLR", "Runtimes"),
        "msvcp100.dll": ("VC++ 2010", "Runtimes"), "msvcr100.dll": ("VC++ 2010", "Runtimes"),
        "msvcp110.dll": ("VC++ 2012", "Runtimes"), "msvcr110.dll": ("VC++ 2012", "Runtimes"),
        "msvcp120.dll": ("VC++ 2013", "Runtimes"), "msvcr120.dll": ("VC++ 2013", "Runtimes"),
        "msvcp140.dll": ("VC++ 2015-22", "Runtimes"), "vcruntime140.dll": ("VC++ 2015-22", "Runtimes"),
        "vcruntime140_1.dll": ("VC++ 2015-22", "Runtimes"),
        "ucrtbase.dll": ("UCRT", "Runtimes"),
        "mono-2.0-bdwgc.dll": ("Mono", "Runtimes"),
        "jvm.dll": ("Java", "Runtimes"),
        "python3.dll": ("Python", "Runtimes"), "python311.dll": ("Python 3.11", "Runtimes"),
        "lua54.dll": ("Lua 5.4", "Runtimes"),
        "xinput1_3.dll": ("XInput 1.3", "Input"), "xinput1_4.dll": ("XInput 1.4", "Input"),
        "dinput8.dll": ("DirectInput", "Input"),
        "sdl2.dll": ("SDL2", "Input"),
        "steam_api.dll": ("Steamworks", "Social/DRM"), "steam_api64.dll": ("Steamworks", "Social/DRM"),
        "galaxy.dll": ("GOG Galaxy", "Social/DRM"), "galaxy64.dll": ("GOG Galaxy", "Social/DRM"),
        "eossdk-win64-shipping.dll": ("Epic", "Social/DRM"),
        "discord_game_sdk.dll": ("Discord", "Social/DRM"),
        "uplay_r1_loader64.dll": ("Ubisoft", "Social/DRM"),
        "unityplayer.dll": ("Unity", "Engines"), "gameassembly.dll": ("Unity IL2CPP", "Engines"),
        "libcef.dll": ("CEF", "Engines"),
        "tier0.dll": ("Source", "Engines"), "vstdlib.dll": ("Source", "Engines"),
        "cryrenderd3d11.dll": ("CryEngine", "Engines"),
        "qt5core.dll": ("Qt 5", "Frameworks"), "qt6core.dll": ("Qt 6", "Frameworks"),
        "electron.dll": ("Electron", "Frameworks"),
        "easyanticheat.dll": ("EAC", "Protection"), "easyanticheat_x64.dll": ("EAC", "Protection"),
        "battleye.dll": ("BattlEye", "Protection"), "beclient_x64.dll": ("BattlEye", "Protection"),
        "vmprotectsdk64.dll": ("VMProtect", "Protection"),
        "denuvo64.dll": ("Denuvo", "Protection"),
    }

    PACKER_SECTIONS = {
        "UPX0": "UPX", "UPX1": "UPX", ".upx": "UPX",
        ".vmp0": "VMProtect", ".vmp1": "VMProtect", "VMP0": "VMProtect",
        ".themida": "Themida",
        ".enigma": "Enigma",
    }

    _yara_rules = None

    def __init__(self, config: BottleConfig):
        self.config = config
        self._load_yara_rules()

    @classmethod
    def _load_yara_rules(cls) -> None:
        """Load YARA rules from the bundled file."""

        logging.info("[Eagle] Reloading YARA rules...")
        rules_path = os.path.join(os.path.dirname(__file__), "eagle.yar")
        if os.path.exists(rules_path):
            try:
                from .native import Rules
                try:
                    cls._yara_rules = Rules(rules_path)
                except FileNotFoundError:
                    import yara
                    cls._yara_rules = yara.compile(filepath=rules_path)
                logging.info("[Eagle] YARA rules loaded")
            except Exception as e:
                logging.warning(f"[Eagle] Failed to load YARA rules: {e}")
                cls._yara_rules = None

    def _is_safe_neighbor_dir(self, directory: str) -> bool:
        """Check if directory is safe for neighbor scanning (not a common clutter folder)."""
        try:
            from gi.repository import GLib
            path = os.path.realpath(directory)
            
            if "/run/user/" in path and "/doc/" in path:
                logging.info(f"[Eagle] Blocking neighbor scan for portal path: {path}")
                return False

            unsafe_dirs = set()
            home = GLib.get_home_dir()
            if home:
                unsafe_dirs.add(os.path.realpath(home))
                for d in ["Downloads", "Desktop", "Documents", "Templates"]:
                    unsafe_dirs.add(os.path.realpath(os.path.join(home, d)))

            for xdg_type in [
                GLib.UserDirectory.DIRECTORY_DOWNLOAD,
                GLib.UserDirectory.DIRECTORY_DESKTOP,
                GLib.UserDirectory.DIRECTORY_DOCUMENTS,
                GLib.UserDirectory.DIRECTORY_TEMPLATES
            ]:
                xdg_path = GLib.get_user_special_dir(xdg_type)
                if xdg_path:
                    unsafe_dirs.add(os.path.realpath(xdg_path))

            if path in unsafe_dirs or path == os.path.realpath(os.path.expanduser("~")):
                logging.info(f"[Eagle] Neighbor scan blocked for unsafe path: {path}")
                return False
                
            return True
        except Exception as e:
            logging.warning(f"[Eagle] Error checking directory safety: {e}")
            return True

    def _send_step(self, msg: str, delay: bool = True) -> None:
        """Send a step update to the UI with optional delay."""
        SignalManager.send(Signals.EagleStep, Result(status=True, data=msg))
        logging.info(f"[Eagle] {msg}")
        if delay:
            time.sleep(STEP_DELAY)

    def _scan_yara(self, file_path: str, insights: dict, source: str = "Main Executable") -> list:
        if self._yara_rules is None: return []
        try:
            from .native import yara_insights
            result = yara_insights(self._yara_rules.rows(file_path, timeout=30), insights, source)
            insights.clear(); insights.update(result['details'])
            for step in result['steps']: self._send_step(step, delay=step.startswith('[!]'))
            return result['matches']
        except Exception as error:
            logging.error(f"[Eagle] YARA scan failed on {file_path}: {error}")
            return []

    def _scan_yara_legacy(self, file_path: str, insights: dict, source: str = "Main Executable") -> list:
        """Run YARA scan on a file and update insights."""
        if self._yara_rules is None:
            return []

        matches = []
        try:
            results = self._yara_rules.match(file_path, timeout=30)
            for match in results:
                category = match.meta.get('category', 'Unknown')
                name = match.meta.get('name', match.rule)
                warning_desc = match.meta.get('description', '')
                severity = match.meta.get('severity', 'info')

                if category not in insights:
                    insights[category] = []
                
                existing_names = [i['name'] for i in insights[category]] if isinstance(insights[category], list) else []
                context = []
                for valid_match in match.strings:
                    ident = None
                    data = None
                    
                    if isinstance(valid_match, tuple):
                        _, ident, data = valid_match
                    else:
                         try:
                             ident = valid_match.identifier
                             if hasattr(valid_match, "instances") and valid_match.instances:
                                 data = valid_match.instances[0].matched_data
                         except:
                             continue
                    
                    rule_name = match.rule
                    should_capture = False
                    
                    if ident and data:
                        if ident == "$capture":
                            should_capture = True
                        elif "key" in ident or "reg" in ident:
                             should_capture = True
                        elif rule_name in ["Node_System_Commands", "Node_Native_Module", "Node_Kernel_Driver", "Driver_Service"]:
                            should_capture = True

                    if should_capture:
                        try:
                            decoded = data.decode('utf-16le') if b'\x00' in data else data.decode('utf-8')
                            clean = decoded.strip().replace('\x00', '')
                            
                            clean_upper = clean.upper()
                            roots = ["HKEY_LOCAL_MACHINE", "HKEY_CURRENT_USER", "HKLM", "HKCU", "HKLM\\", "HKCU\\"]
                            
                            if clean_upper not in roots and len(clean) > 2 and clean not in context:
                                context.append(clean)
                        except:
                            pass
                
                context_list = context[:20]

                if name not in existing_names:
                    if category in ("Warning", "Security"):
                        insights[category].append({
                            "name": name,
                            "description": warning_desc,
                            "severity": severity,
                            "source": source,
                            "context": context_list
                        })
                        self._send_step(f"[!] {name} ({source})")
                    else:
                        insights[category].append({
                            "name": name,
                            "source": source,
                            "context": context_list
                        })
                        self._send_step(f"[{category}] {name} ({source})", delay=False)
                matches.append({"rule": match.rule, "category": category, "name": name, "severity": severity, "source": source})
        except Exception as e:
            logging.error(f"[Eagle] YARA scan failed on {file_path}: {e}")

        return matches

    def security_scan(self, file_path: str) -> list:
        """
        Fast, network-free scan that returns only the Security-category YARA
        matches (potential malware/stealers) for a single file. Used to warn
        the user before running a program. Returns a list of dicts with
        rule/name/description/severity, empty if nothing matched.
        """
        if self._yara_rules is None or not os.path.isfile(file_path):
            return []

        findings = []
        try:
            for match in self._yara_rules.match(file_path, timeout=30):
                if match.meta.get("category") != "Security":
                    continue
                findings.append(
                    {
                        "rule": match.rule,
                        "name": match.meta.get("name", match.rule),
                        "description": match.meta.get("description", ""),
                        "severity": match.meta.get("severity", "warning"),
                    }
                )
        except Exception as e:
            logging.warning(f"[Eagle] security_scan failed on {file_path}: {e}")

        return findings

    def _intel_lookup(self, executable_path: str, pe, product_name: str) -> dict | None:
        intel = EagleIntel()
        if not intel.available:
            return None

        try:
            sha256 = ""
            imphash = ""
            if intel.has_artifacts:
                from .native import artifact_hashes
                hashes = artifact_hashes(executable_path, pe.data['imphash_material'] if pe is not None else '')
                sha256, imphash = hashes['sha256'], hashes['imphash']

            basename = os.path.basename(executable_path)
            hit = intel.lookup(
                sha256=sha256,
                imphash=imphash,
                steam_appid=EagleIntel.find_steam_appid(executable_path),
                product_name=product_name,
                names=[basename.rsplit(".", 1)[0]],
            )
            if hit is None:
                self._send_step(_("No community intelligence match"))
                return None

            plan = intel.plan(hit)
            if plan["source"] == "winetricks":
                self._send_step(
                    _("Known application ({match}): {name}").format(
                        match=plan["match"], name=plan["name"]
                    )
                )
            else:
                self._send_step(
                    _(
                        "Community match ({match}): {name}, tier {tier}, "
                        "{reports} reports"
                    ).format(
                        match=plan["match"],
                        name=plan["name"],
                        tier=plan["tier"],
                        reports=plan["reports"],
                    )
                )
            return plan
        except Exception as e:
            logging.warning(f"[EagleIntel] Analysis lookup failed: {e}")
            return None
        finally:
            intel.close()

    @staticmethod
    def _merge_intel_suggestions(suggestions: list, intel_plan: dict | None) -> None:
        from .native import merge_suggestions
        suggestions[:] = merge_suggestions(suggestions, intel_plan)

    @staticmethod
    def _merge_intel_suggestions_legacy(suggestions: list, intel_plan: dict | None) -> None:
        if not intel_plan:
            return

        suggestions_by_key = {
            suggestion["key"]: suggestion for suggestion in suggestions
        }
        for key, info in intel_plan["parameters"].items():
            evidence = _("{reason} (x{evidence})").format(
                reason=info["reason"], evidence=info["evidence"]
            )
            if key in suggestions_by_key:
                suggestion = suggestions_by_key[key]
                if suggestion["value"] == info["value"]:
                    suggestion["label"] += f" [{evidence}]"
                else:
                    suggestion["label"] = evidence
                suggestion["value"] = info["value"]
                suggestion["apply"] = False
                continue

            suggestion = {
                "key": key,
                "value": info["value"],
                "label": evidence,
                "apply": False,
            }
            suggestions.append(suggestion)
            suggestions_by_key[key] = suggestion

        for dependency in intel_plan["dependencies"]:
            key = f"dep_{dependency['name']}"
            if key in suggestions_by_key:
                continue
            suggestion = {
                "key": key,
                "value": False,
                "label": _("{name} ({reason}, x{evidence})").format(
                    name=dependency["name"],
                    reason=dependency["reason"],
                    evidence=dependency["evidence"],
                ),
            }
            suggestions.append(suggestion)
            suggestions_by_key[key] = suggestion

        for name, info in intel_plan["env"].items():
            suggestions.append(
                {
                    "key": f"intel_env:{name}",
                    "value": info["value"],
                    "label": _(
                        "Set {name}={value} (community evidence x{evidence})"
                    ).format(
                        name=name,
                        value=info["value"],
                        evidence=info["evidence"],
                    ),
                    "apply": False,
                }
            )

        for name, info in intel_plan["dll_overrides"].items():
            suggestions.append(
                {
                    "key": f"intel_dll:{name}",
                    "value": info["value"],
                    "label": _(
                        "Override {name}={value} (community evidence x{evidence})"
                    ).format(
                        name=name,
                        value=info["value"],
                        evidence=info["evidence"],
                    ),
                    "apply": False,
                }
            )

        for argument in intel_plan["args"]:
            suggestions.append(
                {
                    "key": f"intel_arg:{argument['value']}",
                    "value": argument["value"],
                    "label": _(
                        "Add launch argument {argument} "
                        "(community evidence x{evidence})"
                    ).format(
                        argument=argument["value"],
                        evidence=argument["evidence"],
                    ),
                    "apply": False,
                }
            )

    def _extract_asar(self, asar_path: str) -> tuple:
        from .native import extract_asar
        extract_dir = os.path.join(Paths.temp, f"eagle_asar_{uuid.uuid4().hex[:8]}")
        os.makedirs(extract_dir, mode=0o700)
        try:
            self._send_step(f"Extracting ASAR archive: {os.path.basename(asar_path)}...")
            files = extract_asar(asar_path, extract_dir)
            self._send_step(f"Extracted {len(files)} files from ASAR")
            return files, extract_dir
        except Cancelled:
            self._cleanup_extraction(extract_dir)
            raise
        except (ValueError, OSError, RuntimeError) as error:
            logging.warning(f"[Eagle] ASAR extraction failed: {error}")
            self._cleanup_extraction(extract_dir)
            return [], None

    def _extract_installer(self, installer_path: str, installer_type: str) -> tuple:
        """Extract installer and return list of extracted exe/dll paths."""
        extract_dir = os.path.join(Paths.temp, f"eagle_{uuid.uuid4().hex[:8]}")
        os.makedirs(extract_dir, exist_ok=True)
        extracted_files = []

        try:
            self._send_step(f"Extracting {installer_type} installer...")

            seven_z = shutil.which("7z") or shutil.which("7za") or shutil.which("7zr")
            if seven_z:
                cmd = [seven_z, "x", "-y", f"-o{extract_dir}", installer_path]
                
                filters = [
                    "*.exe", "*.dll", "*.msi",
                    "*.json", "*.xml", "*.config", "*.manifest", "*.ini",
                    "*.js", "*.vdf",
                    "*.reg"
                ]
                
                for f in filters:
                    cmd.append(f"-i!{f}")
                    cmd.append(f"-i!**/{f}")
                
                result = run_tool(cmd, capture_output=True, timeout=120)
                if result.returncode != 0:
                    try:
                        patoolib.extract_archive(installer_path, outdir=extract_dir, verbosity=-1)
                    except Exception:
                        raise Exception("Extraction not supported")
            else:
                try:
                    patoolib.extract_archive(installer_path, outdir=extract_dir, verbosity=-1)
                except Exception:
                    raise Exception("No extraction tool available")

            for pattern in ["**/*.exe", "**/*.dll"]:
                extracted_files.extend(glob(os.path.join(extract_dir, pattern), recursive=True))

            self._send_step(f"Found {len(extracted_files)} binaries in installer")

        except Cancelled:
            self._cleanup_extraction(extract_dir)
            raise
        except Exception as e:
            logging.warning(f"[Eagle] Extraction failed: {e}")
            self._send_step("Extraction skipped (not supported)")

        return extracted_files, extract_dir

    def _cleanup_extraction(self, extract_dir: str) -> None:
        """Clean up extracted files."""
        try:
            if extract_dir and os.path.exists(extract_dir):
                shutil.rmtree(extract_dir)
        except Exception as e:
            logging.warning(f"[Eagle] Cleanup failed: {e}")

    def analyze(self, executable_path: str) -> None:
        """Perform comprehensive PE analysis with YARA pattern matching."""
        self._send_step("Initialising Eagle...")
        basename = os.path.basename(executable_path)
        self._send_step(f"Target: {basename}")

        extract_dir = None
        asar_extract_dir = None

        is_msi = basename.lower().endswith(".msi")
        if is_msi:
            self._send_step("MSI package detected - extracting for analysis...")

        try:
            if is_msi:
                insights = {
                    "Graphics": [], "Audio": [], "Runtimes": [], "Input": [],
                    "Social/DRM": [], "Engines": [], "Frameworks": [], "Protection": [],
                    "Packers": [], "Physics": [], "Media": [], "Crypto": [], "Upscaling": [],
                    "Installer": [{"name": "MSI", "source": "File Extension"}], "Warning": [], "Registry": [],
                    "Analysed Files": [basename],
                }
                metadata = {}
                
                extracted_files, extract_dir = self._extract_installer(executable_path, "MSI")
                if extracted_files:
                    settings = Gio.Settings.new(APP_ID)
                    scan_limit = settings.get_int("eagle-scan-limit")
                    files_to_scan = extracted_files[:scan_limit]
                    for i, ef in enumerate(files_to_scan):
                        if not os.path.exists(ef):
                            continue
                        fname = os.path.basename(ef)
                        self._send_step(f"[{i+1}/{len(files_to_scan)}] Scanning: {fname}", delay=False)
                        self._scan_yara(ef, insights, source=fname)

                self._send_step(_("Querying community intelligence..."))
                product_name = basename.rsplit(".", 1)[0]
                intel_plan = self._intel_lookup(
                    executable_path, None, product_name
                )
                suggestions = []
                self._merge_intel_suggestions(suggestions, intel_plan)
                
                results = {
                    "name": basename,
                    "product_name": product_name,
                    "publisher": "Unknown",
                    "arch": "Unknown",
                    "min_os": "Unknown",
                    "admin": False,
                    "frameworks": [],
                    "suggestions": suggestions,
                    "details": insights,
                    "metadata": metadata,
                    "intel": intel_plan,
                }
                self._send_step("MSI analysis complete.")
                SignalManager.send(Signals.EagleFinished, Result(status=True, data=results))
                return

            self._send_step("Loading PE structure (Could take a while)...")
            from .native import PE
            pe = PE(executable_path)
            structure = pe.data

            insights = {
                "Graphics": [], "Audio": [], "Runtimes": [], "Input": [],
                "Social/DRM": [], "Engines": [], "Frameworks": [], "Protection": [],
                "Packers": [], "Physics": [], "Media": [], "Crypto": [], "Upscaling": [],
                "Installer": [], "Warning": [], "Registry": [],
                "Analysed Files": [basename],
            }
            metadata = {
                "compiler": None, "build_date": None, "is_packed": False, "packer": None,
                "large_address_aware": False, "dep_enabled": False, "aslr_enabled": False,
                "is_debug": False,
            }

            from .native import pe_insights
            interpreted = pe_insights(structure, insights, metadata, basename, self.VS_PRODUCTS, self.PACKER_SECTIONS, self.DLL_MAPPINGS)
            insights, metadata = interpreted['details'], interpreted['metadata']
            arch, os_name = interpreted['arch'], interpreted['min_os']
            publisher, product_name = interpreted['publisher'], interpreted['product_name']
            admin_required, dpi_aware, is_net = interpreted['admin'], interpreted['dpi_aware'], interpreted['is_net']
            for step in interpreted['steps']: self._send_step(step)

            self._send_step("Deep pattern scanning (YARA)...")
            yara_matches = self._scan_yara(executable_path, insights)
            if yara_matches:
                self._send_step(f"YARA: {len(yara_matches)} patterns matched")

            self._send_step("Scanning directory structure...")

            from .native import discover
            discovery = discover(executable_path, insights)
            insights = discovery['details']
            ue_shipping_exe = discovery['ue_shipping_exe'] or None
            for step in discovery['steps']:
                self._send_step(step)
            if discovery['asar']:
                asar_path = discovery['asar']

                # Extract and scan ASAR
                self._send_step("Analysing Electron archive...")
                extracted_asar_files, asar_extract_dir = self._extract_asar(asar_path)
                if extracted_asar_files:
                    settings = Gio.Settings.new(APP_ID)
                    scan_limit = settings.get_int("eagle-scan-limit")
                    for i, ef in enumerate(extracted_asar_files[:scan_limit]):
                        fname = os.path.basename(ef)
                        self._send_step(f"Scanning ASAR content: {fname}", delay=False)
                        self._scan_yara(ef, insights, source=f"Electron Source: {fname}")
                    
                    self._cleanup_extraction(asar_extract_dir)

            # Deep Scan for Neighbor Files
            self._send_step("Scanning neighbor files...")
            neighbor_files = discovery['neighbors']
            if not discovery['neighbor_scan_allowed']:
                self._send_step("Skipping neighbor scan (Common directory detected)")

            scan_limit = 20 
            if neighbor_files:
                self._send_step(f"Found {len(neighbor_files)} neighbor files. Ensure directory is clean to avoid false positives.")
                insights["Warning"].append({
                    "name": "Mixed Files Risk",
                    "description": "Neighbor files were analyzed. Ensure all files in this directory belong to the same software to avoid false positives.",
                    "severity": "warning",
                    "source": "Context Scanner"
                })
            
            for i, nf in enumerate(neighbor_files[:scan_limit]):
                fname = os.path.basename(nf)
                # Avoid duplicates
                if fname not in insights["Analysed Files"] and nf != executable_path:
                    self._send_step(f"Scanning context: {fname}", delay=False)
                    self._scan_yara(nf, insights, source=f"Neighbor: {fname}")
                    try: 
                        f_lower = fname.lower()
                        if f_lower in self.DLL_MAPPINGS:
                             name, cat = self.DLL_MAPPINGS[f_lower]
                             existing_names = [x['name'] for x in insights.get(cat, [])]
                             if name not in existing_names:
                                 insights[cat].append({"name": name, "source": f"Neighbor: {fname}"})
                    except:
                        pass
                    insights["Analysed Files"].append(fname)

            extract_dir = None
            if insights["Installer"]:
                installer_item = insights["Installer"][0]
                installer_name = installer_item["name"] if isinstance(installer_item, dict) else str(installer_item)
                self._send_step(f"Installer detected ({installer_name}), performing deep scan...")
                try:
                    extracted_files, extract_dir = self._extract_installer(executable_path, installer_name)
                    if extracted_files:
                        exe_files = [f for f in extracted_files if f.lower().endswith(".exe")]
                        if exe_files:
                            main_exe = max(exe_files, key=os.path.getsize)
                            self._send_step(f"Scanning main binary: {os.path.basename(main_exe)}")

                            settings = Gio.Settings.new(APP_ID)
                            scan_limit = settings.get_int("eagle-scan-limit")
                            files_to_scan = extracted_files[:scan_limit]
                            
                            for i, ef in enumerate(files_to_scan):
                                if not os.path.exists(ef):
                                    continue
                                fname = os.path.basename(ef)
                                insights["Analysed Files"].append(fname)
                                self._send_step(f"[{i+1}/{len(files_to_scan)}] Scanning: {fname}", delay=False)
                                self._scan_yara(ef, insights, source=fname)
                            
                except Exception as e:
                    logging.warning(f"[Eagle] Deep scan failed: {e}")
                    self._send_step(f"Deep scan failed, continuing with surface analysis")

            self._send_step(_("Querying community intelligence..."))
            intel_plan = self._intel_lookup(executable_path, pe, product_name)

            self._send_step("Generating optimisation suggestions...")
            from .native import recommendations
            advice = recommendations(insights, metadata, is_net, dpi_aware, ue_shipping_exe, intel_plan)
            suggestions = advice['suggestions']
            messages = advice['messages']
            frameworks = advice['frameworks']

            results = {
                "name": basename,
                "product_name": product_name,
                "publisher": publisher,
                "arch": arch,
                "min_os": os_name,
                "admin": admin_required,
                "frameworks": frameworks,
                "suggestions": suggestions,
                "messages": messages,
                "details": insights,
                "metadata": metadata,
                "intel": intel_plan,
            }

            self._send_step("Analysis complete.")
            SignalManager.send(Signals.EagleFinished, Result(status=True, data=results))

        except Exception as e:
            self._send_step(f"Error: {str(e)}")
            logging.error(f"[Eagle] {str(e)}")
            SignalManager.send(Signals.EagleFinished, Result(status=False, data={"error": str(e)}))
        finally:
            if extract_dir:
                self._cleanup_extraction(extract_dir)
            if asar_extract_dir:
                self._cleanup_extraction(asar_extract_dir)
