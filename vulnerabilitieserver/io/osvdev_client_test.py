import pytest
from httpx import AsyncClient, Response
from .osvdev_client import OsvDevClient
from vulnerabilitieserver.models.vulnerability import (
    Vulnerability,
    DatabaseSpecific,
    Reference,
    Package,
    Range,
    RangeEvent,
    Severity,
    Affected,
)

FAKE_RESPONSE = {
    "vulns": [
        {
            "id": "GHSA-462w-v97r-4m45",
            "summary": "Jinja2 sandbox escape via string formatting",
            "details": "In Pallets Jinja before 2.10.1, `str.format_map` allows a sandbox escape.\n\nThe sandbox is used to restrict what code can be evaluated when rendering untrusted, user-provided templates. Due to the way string formatting works in Python, the `str.format_map` method could be used to escape the sandbox.\n\nThis issue was previously addressed for the `str.format` method in Jinja 2.8.1, which discusses the issue in detail. However, the less-common `str.format_map` method was overlooked. This release applies the same sandboxing to both methods.\n\nIf you cannot upgrade Jinja, you can override the `is_safe_attribute` method on the sandbox and explicitly disallow the `format_map` method on string objects.",
            "aliases": ["CVE-2019-10906", "PYSEC-2019-217"],
            "modified": "2024-09-24T21:03:59.802687Z",
            "published": "2019-04-10T14:30:24Z",
            "database_specific": {
                "github_reviewed_at": "2020-06-16T20:57:35Z",
                "github_reviewed": True,
                "severity": "HIGH",
                "cwe_ids": ["CWE-693"],
                "nvd_published_at": "2019-04-07T00:29:00Z",
            },
            "references": [
                {
                    "type": "ADVISORY",
                    "url": "https://nvd.nist.gov/vuln/detail/CVE-2019-10906",
                },
                {"type": "WEB", "url": "https://usn.ubuntu.com/4011-2"},
                {"type": "WEB", "url": "https://usn.ubuntu.com/4011-1"},
                {
                    "type": "WEB",
                    "url": "https://palletsprojects.com/blog/jinja-2-10-1-released",
                },
                {
                    "type": "WEB",
                    "url": "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/TS7IVZAJBWOHNRDMFJDIZVFCMRP6YIUQ",
                },
                {
                    "type": "WEB",
                    "url": "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/QCDYIS254EJMBNWOG4S5QY6AOTOR4TZU",
                },
                {
                    "type": "WEB",
                    "url": "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/DSW3QZMFVVR7YE3UT4YRQA272TYAL5AF",
                },
                {
                    "type": "WEB",
                    "url": "https://lists.apache.org/thread.html/f0c4a03418bcfe70c539c5dbaf99c04c98da13bfa1d3266f08564316@%3Ccommits.airflow.apache.org%3E",
                },
                {
                    "type": "WEB",
                    "url": "https://lists.apache.org/thread.html/b2380d147b508bbcb90d2cad443c159e63e12555966ab4f320ee22da@%3Ccommits.airflow.apache.org%3E",
                },
                {
                    "type": "WEB",
                    "url": "https://lists.apache.org/thread.html/7f39f01392d320dfb48e4901db68daeece62fd60ef20955966739993@%3Ccommits.airflow.apache.org%3E",
                },
                {
                    "type": "WEB",
                    "url": "https://lists.apache.org/thread.html/57673a78c4d5c870d3f21465c7e2946b9f8285c7c57e54c2ae552f02@%3Ccommits.airflow.apache.org%3E",
                },
                {
                    "type": "WEB",
                    "url": "https://lists.apache.org/thread.html/46c055e173b52d599c648a98199972dbd6a89d2b4c4647b0500f2284@%3Cdevnull.infra.apache.org%3E",
                },
                {
                    "type": "WEB",
                    "url": "https://lists.apache.org/thread.html/320441dccbd9a545320f5f07306d711d4bbd31ba43dc9eebcfc602df@%3Cdevnull.infra.apache.org%3E",
                },
                {
                    "type": "WEB",
                    "url": "https://lists.apache.org/thread.html/2b52b9c8b9d6366a4f1b407a8bde6af28d9fc73fdb3b37695fd0d9ac@%3Cdevnull.infra.apache.org%3E",
                },
                {
                    "type": "WEB",
                    "url": "https://lists.apache.org/thread.html/09fc842ff444cd43d9d4c510756fec625ef8eb1175f14fd21de2605f@%3Cdevnull.infra.apache.org%3E",
                },
                {
                    "type": "WEB",
                    "url": "https://github.com/pypa/advisory-database/tree/main/vulns/jinja2/PYSEC-2019-217.yaml",
                },
                {"type": "PACKAGE", "url": "https://github.com/pallets/jinja"},
                {
                    "type": "ADVISORY",
                    "url": "https://github.com/advisories/GHSA-462w-v97r-4m45",
                },
                {
                    "type": "WEB",
                    "url": "https://access.redhat.com/errata/RHSA-2019:1329",
                },
                {
                    "type": "WEB",
                    "url": "https://access.redhat.com/errata/RHSA-2019:1237",
                },
                {
                    "type": "WEB",
                    "url": "https://access.redhat.com/errata/RHSA-2019:1152",
                },
                {
                    "type": "WEB",
                    "url": "http://lists.opensuse.org/opensuse-security-announce/2019-05/msg00030.html",
                },
                {
                    "type": "WEB",
                    "url": "http://lists.opensuse.org/opensuse-security-announce/2019-06/msg00064.html",
                },
            ],
            "affected": [
                {
                    "package": {
                        "name": "jinja2",
                        "ecosystem": "PyPI",
                        "purl": "pkg:pypi/jinja2",
                    },
                    "ranges": [
                        {
                            "type": "ECOSYSTEM",
                            "events": [{"introduced": "0"}, {"fixed": "2.10.1"}],
                        }
                    ],
                    "versions": [
                        "2.0",
                        "2.0rc1",
                        "2.1",
                        "2.1.1",
                        "2.10",
                        "2.2",
                        "2.2.1",
                        "2.3",
                        "2.3.1",
                        "2.4",
                        "2.4.1",
                        "2.5",
                        "2.5.1",
                        "2.5.2",
                        "2.5.3",
                        "2.5.4",
                        "2.5.5",
                        "2.6",
                        "2.7",
                        "2.7.1",
                        "2.7.2",
                        "2.7.3",
                        "2.8",
                        "2.8.1",
                        "2.9",
                        "2.9.1",
                        "2.9.2",
                        "2.9.3",
                        "2.9.4",
                        "2.9.5",
                        "2.9.6",
                    ],
                    "database_specific": {
                        "source": "https://github.com/github/advisory-database/blob/main/advisories/github-reviewed/2019/04/GHSA-462w-v97r-4m45/GHSA-462w-v97r-4m45.json"
                    },
                }
            ],
            "schema_version": "1.6.0",
            "severity": [
                {
                    "type": "CVSS_V3",
                    "score": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
                },
                {
                    "type": "CVSS_V4",
                    "score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:H/SI:N/SA:N",
                },
            ],
        },
        {
            "id": "GHSA-8r7q-cvjq-x353",
            "summary": "Incorrect Privilege Assignment in Jinja2",
            "details": "The default configuration for `bccache.FileSystemBytecodeCache` in Jinja2 before 2.7.2 does not properly create temporary files, which allows local users to gain privileges via a crafted .cache file with a name starting with `__jinja2_` in `/tmp`.",
            "aliases": ["CVE-2014-1402", "PYSEC-2014-8"],
            "modified": "2024-09-24T18:48:44.375484Z",
            "published": "2022-05-14T04:04:14Z",
            "database_specific": {
                "github_reviewed_at": "2022-07-07T22:50:31Z",
                "github_reviewed": True,
                "severity": "HIGH",
                "cwe_ids": ["CWE-266"],
                "nvd_published_at": "2014-05-19T14:55:00Z",
            },
            "references": [
                {
                    "type": "ADVISORY",
                    "url": "https://nvd.nist.gov/vuln/detail/CVE-2014-1402",
                },
                {
                    "type": "WEB",
                    "url": "https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=734747",
                },
                {
                    "type": "WEB",
                    "url": "https://bugzilla.redhat.com/show_bug.cgi?id=1051421",
                },
                {
                    "type": "ADVISORY",
                    "url": "https://github.com/advisories/GHSA-8r7q-cvjq-x353",
                },
                {
                    "type": "WEB",
                    "url": "https://github.com/pypa/advisory-database/tree/main/vulns/jinja2/PYSEC-2014-8.yaml",
                },
                {
                    "type": "WEB",
                    "url": "https://oss.oracle.com/pipermail/el-errata/2014-June/004192.html",
                },
                {
                    "type": "WEB",
                    "url": "https://web.archive.org/web/20150523060528/http://www.mandriva.com/en/support/security/advisories/advisory/MDVSA-2014:096/?name=MDVSA-2014:096",
                },
                {
                    "type": "WEB",
                    "url": "http://advisories.mageia.org/MGASA-2014-0028.html",
                },
                {"type": "WEB", "url": "http://jinja.pocoo.org/docs/changelog"},
                {
                    "type": "WEB",
                    "url": "http://openwall.com/lists/oss-security/2014/01/10/2",
                },
                {
                    "type": "WEB",
                    "url": "http://openwall.com/lists/oss-security/2014/01/10/3",
                },
                {
                    "type": "WEB",
                    "url": "http://rhn.redhat.com/errata/RHSA-2014-0747.html",
                },
                {
                    "type": "WEB",
                    "url": "http://rhn.redhat.com/errata/RHSA-2014-0748.html",
                },
                {
                    "type": "WEB",
                    "url": "http://www.gentoo.org/security/en/glsa/glsa-201408-13.xml",
                },
            ],
            "affected": [
                {
                    "package": {
                        "name": "jinja2",
                        "ecosystem": "PyPI",
                        "purl": "pkg:pypi/jinja2",
                    },
                    "ranges": [
                        {
                            "type": "ECOSYSTEM",
                            "events": [{"introduced": "0"}, {"fixed": "2.7.2"}],
                        }
                    ],
                    "versions": [
                        "2.0",
                        "2.0rc1",
                        "2.1",
                        "2.1.1",
                        "2.2",
                        "2.2.1",
                        "2.3",
                        "2.3.1",
                        "2.4",
                        "2.4.1",
                        "2.5",
                        "2.5.1",
                        "2.5.2",
                        "2.5.3",
                        "2.5.4",
                        "2.5.5",
                        "2.6",
                        "2.7",
                        "2.7.1",
                    ],
                    "database_specific": {
                        "source": "https://github.com/github/advisory-database/blob/main/advisories/github-reviewed/2022/05/GHSA-8r7q-cvjq-x353/GHSA-8r7q-cvjq-x353.json"
                    },
                }
            ],
            "schema_version": "1.6.0",
            "severity": [
                {
                    "type": "CVSS_V3",
                    "score": "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                },
                {
                    "type": "CVSS_V4",
                    "score": "CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
                },
            ],
        },
    ]
}


@pytest.mark.asyncio
async def test_find_vulnerabilities_calls_correct_url_and_data(respx_mock):
    osv_client = OsvDevClient(AsyncClient())
    respx_mock.post("https://api.osv.dev/v1/query").mock(
        return_value=Response(204, json=FAKE_RESPONSE)
    )

    vulnerabilities = await osv_client.find_vulnerabilities("2.0.0", "foo", "PyPI")
    print(vulnerabilities)
    assert vulnerabilities == [
        Vulnerability(
            id="GHSA-462w-v97r-4m45",
            summary="Jinja2 sandbox escape via string formatting",
            details="In Pallets Jinja before 2.10.1, `str.format_map` allows a sandbox escape.\n\nThe sandbox is used to restrict what code can be evaluated when rendering untrusted, user-provided templates. Due to the way string formatting works in Python, the `str.format_map` method could be used to escape the sandbox.\n\nThis issue was previously addressed for the `str.format` method in Jinja 2.8.1, which discusses the issue in detail. However, the less-common `str.format_map` method was overlooked. This release applies the same sandboxing to both methods.\n\nIf you cannot upgrade Jinja, you can override the `is_safe_attribute` method on the sandbox and explicitly disallow the `format_map` method on string objects.",
            aliases=["CVE-2019-10906", "PYSEC-2019-217"],
            modified="2024-09-24T21:03:59.802687Z",
            published="2019-04-10T14:30:24Z",
            database_specific=DatabaseSpecific(
                github_reviewed_at="2020-06-16T20:57:35Z",
                github_reviewed=True,
                severity="HIGH",
                cwe_ids=["CWE-693"],
                nvd_published_at="2019-04-07T00:29:00Z",
                source=None,
            ),
            references=[
                Reference(
                    type="ADVISORY",
                    url="https://nvd.nist.gov/vuln/detail/CVE-2019-10906",
                ),
                Reference(type="WEB", url="https://usn.ubuntu.com/4011-2"),
                Reference(type="WEB", url="https://usn.ubuntu.com/4011-1"),
                Reference(
                    type="WEB",
                    url="https://palletsprojects.com/blog/jinja-2-10-1-released",
                ),
                Reference(
                    type="WEB",
                    url="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/TS7IVZAJBWOHNRDMFJDIZVFCMRP6YIUQ",
                ),
                Reference(
                    type="WEB",
                    url="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/QCDYIS254EJMBNWOG4S5QY6AOTOR4TZU",
                ),
                Reference(
                    type="WEB",
                    url="https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/DSW3QZMFVVR7YE3UT4YRQA272TYAL5AF",
                ),
                Reference(
                    type="WEB",
                    url="https://lists.apache.org/thread.html/f0c4a03418bcfe70c539c5dbaf99c04c98da13bfa1d3266f08564316@%3Ccommits.airflow.apache.org%3E",
                ),
                Reference(
                    type="WEB",
                    url="https://lists.apache.org/thread.html/b2380d147b508bbcb90d2cad443c159e63e12555966ab4f320ee22da@%3Ccommits.airflow.apache.org%3E",
                ),
                Reference(
                    type="WEB",
                    url="https://lists.apache.org/thread.html/7f39f01392d320dfb48e4901db68daeece62fd60ef20955966739993@%3Ccommits.airflow.apache.org%3E",
                ),
                Reference(
                    type="WEB",
                    url="https://lists.apache.org/thread.html/57673a78c4d5c870d3f21465c7e2946b9f8285c7c57e54c2ae552f02@%3Ccommits.airflow.apache.org%3E",
                ),
                Reference(
                    type="WEB",
                    url="https://lists.apache.org/thread.html/46c055e173b52d599c648a98199972dbd6a89d2b4c4647b0500f2284@%3Cdevnull.infra.apache.org%3E",
                ),
                Reference(
                    type="WEB",
                    url="https://lists.apache.org/thread.html/320441dccbd9a545320f5f07306d711d4bbd31ba43dc9eebcfc602df@%3Cdevnull.infra.apache.org%3E",
                ),
                Reference(
                    type="WEB",
                    url="https://lists.apache.org/thread.html/2b52b9c8b9d6366a4f1b407a8bde6af28d9fc73fdb3b37695fd0d9ac@%3Cdevnull.infra.apache.org%3E",
                ),
                Reference(
                    type="WEB",
                    url="https://lists.apache.org/thread.html/09fc842ff444cd43d9d4c510756fec625ef8eb1175f14fd21de2605f@%3Cdevnull.infra.apache.org%3E",
                ),
                Reference(
                    type="WEB",
                    url="https://github.com/pypa/advisory-database/tree/main/vulns/jinja2/PYSEC-2019-217.yaml",
                ),
                Reference(type="PACKAGE", url="https://github.com/pallets/jinja"),
                Reference(
                    type="ADVISORY",
                    url="https://github.com/advisories/GHSA-462w-v97r-4m45",
                ),
                Reference(
                    type="WEB", url="https://access.redhat.com/errata/RHSA-2019:1329"
                ),
                Reference(
                    type="WEB", url="https://access.redhat.com/errata/RHSA-2019:1237"
                ),
                Reference(
                    type="WEB", url="https://access.redhat.com/errata/RHSA-2019:1152"
                ),
                Reference(
                    type="WEB",
                    url="http://lists.opensuse.org/opensuse-security-announce/2019-05/msg00030.html",
                ),
                Reference(
                    type="WEB",
                    url="http://lists.opensuse.org/opensuse-security-announce/2019-06/msg00064.html",
                ),
            ],
            affected=[
                Affected(
                    package=Package(
                        name="jinja2", ecosystem="PyPI", purl="pkg:pypi/jinja2"
                    ),
                    ranges=[
                        Range(
                            type="ECOSYSTEM",
                            events=[
                                RangeEvent(introduced="0", fixed=None),
                                RangeEvent(introduced=None, fixed="2.10.1"),
                            ],
                        )
                    ],
                    versions=[
                        "2.0",
                        "2.0rc1",
                        "2.1",
                        "2.1.1",
                        "2.10",
                        "2.2",
                        "2.2.1",
                        "2.3",
                        "2.3.1",
                        "2.4",
                        "2.4.1",
                        "2.5",
                        "2.5.1",
                        "2.5.2",
                        "2.5.3",
                        "2.5.4",
                        "2.5.5",
                        "2.6",
                        "2.7",
                        "2.7.1",
                        "2.7.2",
                        "2.7.3",
                        "2.8",
                        "2.8.1",
                        "2.9",
                        "2.9.1",
                        "2.9.2",
                        "2.9.3",
                        "2.9.4",
                        "2.9.5",
                        "2.9.6",
                    ],
                    database_specific=DatabaseSpecific(
                        github_reviewed_at=None,
                        github_reviewed=None,
                        severity=None,
                        cwe_ids=None,
                        nvd_published_at=None,
                        source="https://github.com/github/advisory-database/blob/main/advisories/github-reviewed/2019/04/GHSA-462w-v97r-4m45/GHSA-462w-v97r-4m45.json",
                    ),
                )
            ],
            schema_version="1.6.0",
            severity=[
                Severity(
                    type="CVSS_V3", score="CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N"
                ),
                Severity(
                    type="CVSS_V4",
                    score="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:H/SI:N/SA:N",
                ),
            ],
        ),
        Vulnerability(
            id="GHSA-8r7q-cvjq-x353",
            summary="Incorrect Privilege Assignment in Jinja2",
            details="The default configuration for `bccache.FileSystemBytecodeCache` in Jinja2 before 2.7.2 does not properly create temporary files, which allows local users to gain privileges via a crafted .cache file with a name starting with `__jinja2_` in `/tmp`.",
            aliases=["CVE-2014-1402", "PYSEC-2014-8"],
            modified="2024-09-24T18:48:44.375484Z",
            published="2022-05-14T04:04:14Z",
            database_specific=DatabaseSpecific(
                github_reviewed_at="2022-07-07T22:50:31Z",
                github_reviewed=True,
                severity="HIGH",
                cwe_ids=["CWE-266"],
                nvd_published_at="2014-05-19T14:55:00Z",
                source=None,
            ),
            references=[
                Reference(
                    type="ADVISORY",
                    url="https://nvd.nist.gov/vuln/detail/CVE-2014-1402",
                ),
                Reference(
                    type="WEB",
                    url="https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=734747",
                ),
                Reference(
                    type="WEB",
                    url="https://bugzilla.redhat.com/show_bug.cgi?id=1051421",
                ),
                Reference(
                    type="ADVISORY",
                    url="https://github.com/advisories/GHSA-8r7q-cvjq-x353",
                ),
                Reference(
                    type="WEB",
                    url="https://github.com/pypa/advisory-database/tree/main/vulns/jinja2/PYSEC-2014-8.yaml",
                ),
                Reference(
                    type="WEB",
                    url="https://oss.oracle.com/pipermail/el-errata/2014-June/004192.html",
                ),
                Reference(
                    type="WEB",
                    url="https://web.archive.org/web/20150523060528/http://www.mandriva.com/en/support/security/advisories/advisory/MDVSA-2014:096/?name=MDVSA-2014:096",
                ),
                Reference(
                    type="WEB", url="http://advisories.mageia.org/MGASA-2014-0028.html"
                ),
                Reference(type="WEB", url="http://jinja.pocoo.org/docs/changelog"),
                Reference(
                    type="WEB",
                    url="http://openwall.com/lists/oss-security/2014/01/10/2",
                ),
                Reference(
                    type="WEB",
                    url="http://openwall.com/lists/oss-security/2014/01/10/3",
                ),
                Reference(
                    type="WEB", url="http://rhn.redhat.com/errata/RHSA-2014-0747.html"
                ),
                Reference(
                    type="WEB", url="http://rhn.redhat.com/errata/RHSA-2014-0748.html"
                ),
                Reference(
                    type="WEB",
                    url="http://www.gentoo.org/security/en/glsa/glsa-201408-13.xml",
                ),
            ],
            affected=[
                Affected(
                    package=Package(
                        name="jinja2", ecosystem="PyPI", purl="pkg:pypi/jinja2"
                    ),
                    ranges=[
                        Range(
                            type="ECOSYSTEM",
                            events=[
                                RangeEvent(introduced="0", fixed=None),
                                RangeEvent(introduced=None, fixed="2.7.2"),
                            ],
                        )
                    ],
                    versions=[
                        "2.0",
                        "2.0rc1",
                        "2.1",
                        "2.1.1",
                        "2.2",
                        "2.2.1",
                        "2.3",
                        "2.3.1",
                        "2.4",
                        "2.4.1",
                        "2.5",
                        "2.5.1",
                        "2.5.2",
                        "2.5.3",
                        "2.5.4",
                        "2.5.5",
                        "2.6",
                        "2.7",
                        "2.7.1",
                    ],
                    database_specific=DatabaseSpecific(
                        github_reviewed_at=None,
                        github_reviewed=None,
                        severity=None,
                        cwe_ids=None,
                        nvd_published_at=None,
                        source="https://github.com/github/advisory-database/blob/main/advisories/github-reviewed/2022/05/GHSA-8r7q-cvjq-x353/GHSA-8r7q-cvjq-x353.json",
                    ),
                )
            ],
            schema_version="1.6.0",
            severity=[
                Severity(
                    type="CVSS_V3", score="CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
                ),
                Severity(
                    type="CVSS_V4",
                    score="CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
                ),
            ],
        ),
    ]
