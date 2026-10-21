use crate::ui::{fmt_bytes, info, ok, warn, yellow};

pub fn calc_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let n = data.len() as f64;
    let mut entropy = 0.0;
    for &c in &counts {
        if c > 0 {
            let p = c as f64 / n;
            entropy -= p * p.log2();
        }
    }
    entropy
}

pub fn lower_entropy_raw(data: &[u8], target: f64) -> (Vec<u8>, Option<usize>) {
    let current = calc_entropy(data);
    if current <= target {
        return (data.to_vec(), None);
    }

    let mut chosen_interval = None;
    let mut chosen_result = None;

    let intervals = [16, 12, 8, 6, 4, 3, 2, 1];
    for &interval in &intervals {
        let mut result = Vec::with_capacity(data.len() + data.len() / interval + 1);
        for (i, &byte) in data.iter().enumerate() {
            result.push(byte);
            if (i + 1) % interval == 0 {
                result.push(0x00);
            }
        }
        let achieved = calc_entropy(&result);
        if achieved <= target {
            chosen_interval = Some(interval);
            chosen_result = Some(result);
        }
    }

    if chosen_result.is_none() {
        chosen_interval = Some(1);
        let mut result = Vec::with_capacity(data.len() * 2);
        for &byte in data {
            result.push(byte);
            result.push(0x00);
        }
        chosen_result = Some(result);
    }

    (chosen_result.unwrap(), chosen_interval)
}

pub fn lower_entropy(data: &[u8], target: f64) -> (Vec<u8>, Option<usize>) {
    let current = calc_entropy(data);
    if current <= target {
        info(&format!(
            "Entropy already {:.3} — no null insertion needed.",
            current
        ));
        return (data.to_vec(), None);
    }

    info(&format!("Current entropy : {:.3}", current));
    info(&format!("Target entropy  : {:.3}", target));

    let (result, chosen_interval) = lower_entropy_raw(data, target);
    let interval = chosen_interval.unwrap();

    let final_entropy = calc_entropy(&result);
    let size_increase = result.len() - data.len();
    let pct = if data.is_empty() {
        0
    } else {
        (100 * size_increase) / data.len()
    };

    ok(&format!(
        "Entropy reduced : {:.3} → {:.3}",
        current, final_entropy
    ));
    ok(&format!(
        "Null interval   : 1 null per {} byte(s)",
        interval
    ));
    ok(&format!(
        "Size increase   : {} (+{}%)",
        fmt_bytes(size_increase as u64),
        pct
    ));
    println!();
    println!(
        "{}",
        yellow("  ⚠  Save this interval — needed to recover the original:")
    );
    println!(
        "{}",
        yellow(&format!(
            "     python cloak.py util -c <padded_file> --strip-padding {}",
            interval
        ))
    );
    println!();

    (result, Some(interval))
}

pub fn strip_null_padding_raw(data: &[u8], interval: usize) -> Result<Vec<u8>, String> {
    if interval < 1 {
        return Err("Interval must be >= 1.".to_string());
    }

    let mut result = Vec::with_capacity(data.len());
    let mut group_pos = 0;
    let mut i = 0;

    while i < data.len() {
        result.push(data[i]);
        group_pos += 1;
        i += 1;
        if group_pos == interval && i < data.len() {
            // Skip the inserted null
            i += 1;
            group_pos = 0;
        }
    }

    Ok(result)
}

pub fn strip_null_padding(data: &[u8], interval: usize) -> Result<Vec<u8>, String> {
    let result = strip_null_padding_raw(data, interval)?;

    // Sanity check via formula
    let expected = (data.len() * interval) / (interval + 1);
    let diff = (result.len() as isize - expected as isize).abs();
    if diff > interval as isize {
        warn(&format!(
            "Recovered size {} differs from expected {} — interval may be wrong.",
            result.len(),
            expected
        ));
    }

    ok(&format!(
        "Padding stripped : interval was 1 null per {} byte(s)",
        interval
    ));
    ok(&format!(
        "Recovered size   : {} ({} bytes)",
        fmt_bytes(result.len() as u64),
        result.len()
    ));

    Ok(result)
}
