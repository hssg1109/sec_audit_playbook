# ASM Script Index

This is the primary execution surface for DAST/ASM runs (repo `~/Downloads/asm/scripts/`).

Core orchestration:
- `90_full_run_and_confluence.sh`: full pipeline + Confluence update
- `91_root_run.sh`: run pipeline for a single root
- `92_roots_batch.sh`: batch run for roots file

Seed/inputs:
- `10_conf_enrich.sh`: enrich roots/wordlists from internal configs
- `11_pitsm_fetch.sh`: fetch PITSM issues
- `12_pitsm_parse_dns.sh`: parse DNS requests
- `13_pitsm_validate.sh`: validate DNS request outputs
- `14_pitsm_merge_manual.sh`: merge manual PITSM data
- `15_mandiant_asm_fetch.sh`: fetch ASM seeds
- `16_asm_seed_merge.sh`: merge ASM seeds
- `17_dnsx_resolve.sh`: resolve domains to IPs
- `18_merge_resolved_ips.sh`: merge resolved IPs

URL track:
- `20_crtsh_collect.sh`
- `21_certspotter_collect.sh`
- `30_shuffledns_bruteforce.sh`
- `40_merge_subs.sh`
- `50_httpx_live.sh`
- `60_merge_live_urls.sh`
- `70_nextjs_scan.sh`

IP track:
- `80_swadagent_scan.sh`
- `82_cve_2026_24061_scan.sh`

Reporting inputs:
- `85_kibana_firewall_stats.sh`

Normalize outputs to SARIF after each scan batch.
