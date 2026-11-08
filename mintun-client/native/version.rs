use anyhow::{Result, ensure};
use std::cmp::Ordering;

#[derive(Clone)]
struct Version<'a> { numbers: [&'a str; 3], pre: Vec<&'a str> }
fn numeric(s: &str) -> bool { !s.is_empty() && s.bytes().all(|c| c.is_ascii_digit()) }
fn number_cmp(a: &str, b: &str) -> Ordering { a.len().cmp(&b.len()).then_with(|| a.cmp(b)) }
fn parse(text: &str) -> Result<Version<'_>> {
    ensure!(text.len() <= 200, "Version exceeds 200 characters");
    let text = text.strip_prefix('v').unwrap_or(text);
    let (version, build) = text.split_once('+').map_or((text, None), |(a,b)| (a, Some(b)));
    let valid_ids = |s: &str| !s.is_empty() && s.split('.').all(|p| !p.is_empty() && p.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-'));
    if let Some(build) = build { ensure!(valid_ids(build), "Invalid version build metadata"); }
    let (base, pre) = version.split_once('-').map_or((version, None), |(a,b)| (a,Some(b)));
    let parts: Vec<_> = base.split('.').collect();
    ensure!(parts.len() == 3 && parts.iter().all(|s| numeric(s) && (s.len() == 1 || !s.starts_with('0'))), "Invalid semantic version");
    let pre = if let Some(pre) = pre {
        ensure!(valid_ids(pre), "Invalid prerelease version");
        let ids: Vec<_> = pre.split('.').collect();
        ensure!(ids.iter().all(|s| !numeric(s) || s.len() == 1 || !s.starts_with('0')), "Leading zero in prerelease version");
        ids
    } else { Vec::new() };
    Ok(Version { numbers: [parts[0], parts[1], parts[2]], pre })
}
pub fn normalize(text: &str) -> Result<&str> { parse(text)?; Ok(text.strip_prefix('v').unwrap_or(text)) }
pub fn is_prerelease(text: &str) -> Result<bool> { Ok(!parse(text)?.pre.is_empty()) }
pub fn compare(a: &str, b: &str) -> Result<Ordering> {
    let a = parse(a)?; let b = parse(b)?;
    for (a,b) in a.numbers.iter().zip(b.numbers.iter()) { let n = number_cmp(a,b); if n != Ordering::Equal { return Ok(n); } }
    match (a.pre.is_empty(), b.pre.is_empty()) { (true,false) => return Ok(Ordering::Greater), (false,true) => return Ok(Ordering::Less), _ => {} }
    for (a,b) in a.pre.iter().zip(b.pre.iter()) {
        let n = match (numeric(a),numeric(b)) { (true,true) => number_cmp(a,b), (true,false) => Ordering::Less, (false,true) => Ordering::Greater, _ => a.cmp(b) };
        if n != Ordering::Equal { return Ok(n); }
    }
    Ok(a.pre.len().cmp(&b.pre.len()))
}
pub fn compatible(actual: &str, minimum: &str) -> Result<bool> { Ok(compare(actual,minimum)? != Ordering::Less) }

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn semantic_ordering_and_unbounded_numbers() {
        let versions = ["1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta", "1.0.0-beta.2", "1.0.0-beta.11", "1.0.0-rc.1", "1.0.0", "999999999999999999999999999999.0.0"];
        for pair in versions.windows(2) { assert_eq!(compare(pair[0],pair[1]).unwrap(),Ordering::Less); }
        assert_eq!(compare("v1.0.0+a","1.0.0+b").unwrap(),Ordering::Equal);
    }
    #[test] fn rejects_invalid_versions() {
        for bad in ["1.0", "01.0.0", "1.0.0-01", "1.0.0+", "1.0.0+x+y", " 1.0.0", "1.0.0-a..b"] { assert!(compare(bad,"1.0.0").is_err(), "{bad}"); }
    }
}
