"""Pinned SHA-256 allowlist for the Indian CCA hierarchy. Reviewed constants, never fetched.

Anchor, Capricorn and old-root pins were verified by research against the CCA site, the Capricorn repository, the IDSign
repository and Adobe AATL, and recomputed from the bundled files in tests. The `other_ca` pins (other licensed CAs' 2022 CA
certs, https://cca.gov.in/display_cert2022.php) have CCA-only provenance: each file was hashed locally, and tests check that
every one is signed by the pinned anchor. They are intermediates only and are never trust anchors.

NEVER add: CCA India 2022 SPL, 2015 SPL, 2007, 2002.
"""

from dataclasses import dataclass

# Cross-check only (a test compares it with the bundled file); SHA-1 is never used for a trust decision, the SHA-256 pins are.
ANCHOR_SHA1 = "a79e41380bab3ed7f5188d9a5209cefcb3ca6991"  # Microsoft's published value for CCA India 2022
CCA_URL = "https://cca.gov.in/cca/sites/default/files/files/CCAIndia2022.cer"
CAPRICORN_URL = "https://www.certificate.digital/repository/"
ALLOWED_HOSTS = ("cca.gov.in", "www.certificate.digital")


@dataclass(frozen=True)
class Pin:
    name: str
    filename: str  # DER file under trust/certs/
    sha256: str  # upper-case hex, no colons
    role: str  # anchor | capricorn | old_root | other_ca
    url: str = ""  # official download URL ("" = bundled only)


def _h(colon):
    return colon.replace(":", "").upper()


ANCHOR = Pin(
    "CCA India 2022",
    "CCAIndia2022.der",
    _h("9A:3F:D3:17:67:98:E8:42:DD:CB:12:C2:62:F1:1C:FA:CC:A7:0A:8B:84:C6:EA:6F:DA:30:84:2A:95:A9:4C:D8"),
    "anchor",
    CCA_URL,
)

CAPRICORN = (
    Pin(
        "Capricorn CA 2022",
        "CapricornCA2022.der",
        _h("E3:02:C8:E2:48:1E:9F:12:67:B0:6E:92:74:25:39:C6:C3:6B:A9:DB:C4:CB:8C:31:5C:8D:58:20:B7:24:91:B2"),
        "capricorn",
        CAPRICORN_URL + "CapricornCA2022.cer",
    ),
    Pin(
        "Capricorn Sub CA for Individual DSC 2022",
        "CapricornSubCAforIndividualDSC2022.der",
        _h("A9:A4:2F:25:E4:17:2F:86:9D:93:4B:2B:1D:D4:70:F2:92:54:80:11:9E:07:F1:32:22:EA:6F:94:DE:49:A7:2B"),
        "capricorn",
        CAPRICORN_URL + "CapricornSubCAforIndividualDSC2022.cer",
    ),
    Pin(
        "Capricorn Sub CA for Organisation DSC 2022",
        "CapricornSubCAforOrganizationDSC2022.der",
        _h("54:7C:58:52:81:26:AE:D0:D6:C4:BE:C1:4E:A7:DD:8F:49:D9:5E:2C:52:24:99:EC:90:22:70:1F:76:29:A6:7D"),
        "capricorn",
        CAPRICORN_URL + "CapricornSubCAforOrganizationDSC2022.cer",
    ),  # the file name is spelled 'Organization'
    Pin(
        "Capricorn Sub CA for Document Signer DSC 2022",
        "CapricornSubCAforDocumentSignerDSC2022.der",
        _h("7C:1C:A6:9F:26:05:44:12:14:8E:F3:81:F4:5B:B9:19:69:8D:55:AF:FC:43:57:83:CD:66:22:BD:7E:A3:4F:00"),
        "capricorn",
        CAPRICORN_URL + "CapricornSubCAforDocumentSignerDSC2022.cer",
    ),
    Pin(
        "Capricorn Sub CA for TSA 2022",
        "CapricornSubCAforTSA2022.der",
        _h("3F:9E:47:35:F9:EC:10:7B:F4:F9:04:3A:F0:5D:6E:78:39:FD:6D:4D:B6:3F:D0:D9:B9:06:26:57:4E:42:31:A0"),
        "capricorn",
        CAPRICORN_URL + "CapricornSubCAforTSA2022.cer",
    ),
)

# Expired roots: opt-in, to validate OLD documents only.
OLD_ROOTS = (
    Pin(
        "CCA India 2014",
        "CCAIndia2014.der",
        _h("60:10:9B:C6:C3:83:28:59:8A:11:2C:7A:25:E3:8B:0F:23:E5:A7:51:1C:B8:15:FB:64:E0:C4:FF:05:DB:7D:F7"),
        "old_root",
    ),
    Pin(
        "CCA India 2011",
        "cca_india_2011.der",
        _h("2D:66:A7:02:AE:81:BA:03:AF:8C:FF:55:AB:31:8A:FA:91:90:39:D9:F3:1B:4D:64:38:86:80:F8:13:11:B6:5A"),
        "old_root",
    ),
)

OTHER_CAS = (
    Pin("C-DAC CA 2022", "CDAC_CA.der", "462F390B10E94EA0A733E81BCA5D9E6EC3CE73C46B205F9E7CE70A9853844B38", "other_ca"),
    Pin("CDSL Ventures Limited CA 2022-1", "CDSL_CA_2022.der", "E7FAAE038091C097A41ADCCE9C93DE6387A4B2875E8718C25A18022BF66942A1", "other_ca"),
    Pin(
        "CDSL Ventures Limited CA 2022",
        "CDSL_Ventures_Limited_CA.der",
        "F2A0A08922C2356F6ED6AC29DD3E618B116AAF9AA5F317F7F5AF168F3A1C58EC",
        "other_ca",
    ),
    Pin("CSC CA 2022", "CSC_CA_2022.der", "B02FE7034B094D8FA4F3C658F2FE3FC1C84C019934DEFD9A1367DA9D9C15CF94", "other_ca"),
    Pin("Care4Sign CA 2022", "Care4sign-CA-2022.der", "FEC666FACEDDC60FD2FC189A4CD7137C986D74A186FC82980B4C538B80075EC8", "other_ca"),
    Pin("IDRBT CA 2022", "IDRBT_CA_2022.der", "E4173980F9178208A2AA1061A71707036B26BCF5531F39D6DF3C486DCE8A7F4C", "other_ca"),
    Pin("IDSign CA 2022", "IDSign_CA_2022.der", "F0E3FEEF7DAE7481ECEB61B45355D6954C5CCD80B60341A48A70537AEC1F9DBA", "other_ca"),
    Pin("IGCAR CA 2022", "IGCAR_CA_2022.der", "BC48D885AEA1D8F89B6E04061951806ED3DF781EE9CCA745ADF403BF034E4C2C", "other_ca"),
    Pin("JPSL CA 2022", "JPSL__CA__2022_.der", "A48EC891AE77FA6E42DA166FEF11FFB4E582834280E8FD52FDAD1AE80C56A787", "other_ca"),
    Pin("PantaSign CA 2022", "PantaSign_CA_2022.der", "E1232769DABA91EAE7EAF2D0CF5B416E28B6C2F235BF76F4848E4EF5B1BD3048", "other_ca"),
    Pin("ProDigiSign CA 2022", "ProDigiSign-CA-2022.der", "B3A0D165173A0718C5A8D20104BD34A6A74A21704053F3AF25ECA780DC73621D", "other_ca"),
    Pin("Protean eGov CA 2022", "Protean_eGov_CA.der", "A9022C0BFC0AF4C5F58410E72F81EAC154F8AD1C4E9173A8A75F9FEDFF053056", "other_ca"),
    Pin("RajComp CA 2022", "RajComp_CA_2022.der", "A72654E7FA756473654D8379E12FDF8ED2DE2392B73E3EFDEAF45AA5048DE2D7", "other_ca"),
    Pin("SafeScrypt CA 2022", "Sify_Safecrypt_CA_2022.der", "66D2C07740525F4524D1617758F9C316AD2B955EEEC792EF493CE64C4AD99EFA", "other_ca"),
    Pin("SignX CA 2022", "SignX_CA_2022.der", "A8D6363AFEB8FE0FC8B627022954D5681872EA4D998E59B3D8395ABCC3953452", "other_ca"),
    Pin(
        "Speed Sign Technologies Pvt Ltd CA 2022",
        "Speed_Sign_2022.der",
        "D00CA8D89F7E70897A8DA008ED9317CD7C5D5BD73047618D7F5F8BEA704D9637",
        "other_ca",
    ),
    Pin("Verasys CA 2022", "Verasys_CA_2022.der", "BC2FD40CE175D9AB65DEECBCC8BB2472DC727F89906FFFFBEBC1D916C9072F6D", "other_ca"),
    Pin("XtraTrust CA 2022", "XtratrustCA2022.der", "3B6A80DAAAB740B989A8F5B7F9B16123B604797D8CEFAC52B5D764C13CA5767F", "other_ca"),
    Pin("e-Mudhra CA 2022", "e-Mudhra_CA_2022.der", "21BE69EAF1B6376274087AEB6A0B0CA3C1DBFD3AC1AC518BEF38EEBBB2B80CD3", "other_ca"),
    Pin("(n)Code Solutions CA 2022", "nCode_Solutions_CA_2022.der", "89277300F4CA8511D6B4585D62C4FF6F765477169928C5BEF49A88958A392595", "other_ca"),
)

ALL = (ANCHOR, *CAPRICORN, *OLD_ROOTS, *OTHER_CAS)
INTERMEDIATES = (*CAPRICORN, *OTHER_CAS)
