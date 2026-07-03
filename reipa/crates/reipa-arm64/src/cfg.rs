use crate::{Flow, Insn};
use std::collections::BTreeSet;

pub struct Block {
    pub start: u64,
    pub insns: Vec<Insn>,
    pub succ: Vec<u64>,
}

pub fn build_blocks(insns: &[Insn]) -> Vec<Block> {
    if insns.is_empty() {
        return Vec::new();
    }
    let lo = insns.first().map(|i| i.addr).unwrap_or(0);
    let hi = insns.last().map(|i| i.addr + 4).unwrap_or(0);
    let in_range = |a: u64| a >= lo && a < hi;

    let mut leaders: BTreeSet<u64> = BTreeSet::new();
    leaders.insert(insns[0].addr);
    for (idx, ins) in insns.iter().enumerate() {
        let next = ins.addr + 4;
        match &ins.flow {
            Flow::Branch(t) | Flow::CondBranch(t) => {
                if in_range(*t) {
                    leaders.insert(*t);
                }
                if idx + 1 < insns.len() {
                    leaders.insert(next);
                }
            }
            Flow::Call(_) | Flow::IndirectCall | Flow::Return | Flow::Indirect => {
                if idx + 1 < insns.len() {
                    leaders.insert(next);
                }
            }
            Flow::Fallthrough => {}
        }
    }

    let mut blocks: Vec<Block> = Vec::new();
    let mut cur: Vec<Insn> = Vec::new();
    let mut start = insns[0].addr;
    for (idx, ins) in insns.iter().enumerate() {
        if leaders.contains(&ins.addr) && !cur.is_empty() {
            let s = start;
            blocks.push(Block {
                start: s,
                insns: std::mem::take(&mut cur),
                succ: vec![ins.addr],
            });
            start = ins.addr;
        }
        let flow = ins.flow.clone();
        cur.push(ins.clone());
        let is_last = idx + 1 == insns.len();
        let terminates = !matches!(flow, Flow::Fallthrough | Flow::Call(_) | Flow::IndirectCall);
        if terminates || is_last {
            let next = ins.addr + 4;
            let succ = match flow {
                Flow::Branch(t) => filt(&[t], in_range),
                Flow::CondBranch(t) => filt(&[t, next], in_range),
                Flow::Return | Flow::Indirect => Vec::new(),
                Flow::Call(_) | Flow::IndirectCall | Flow::Fallthrough => filt(&[next], in_range),
            };
            blocks.push(Block {
                start,
                insns: std::mem::take(&mut cur),
                succ,
            });
            start = next;
        }
    }
    if !cur.is_empty() {
        blocks.push(Block {
            start,
            insns: cur,
            succ: Vec::new(),
        });
    }
    blocks
}

fn filt(addrs: &[u64], in_range: impl Fn(u64) -> bool) -> Vec<u64> {
    addrs.iter().copied().filter(|a| in_range(*a)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decode;

    #[test]
    fn splits_on_conditional_branch() {
        let insns = vec![
            decode(0x34000040, 0x1000),
            decode(0xD2800021, 0x1004),
            decode(0xD65F03C0, 0x1008),
        ];
        let blocks = build_blocks(&insns);
        assert_eq!(blocks[0].start, 0x1000);
        assert!(blocks[0].succ.contains(&0x1008));
        assert!(blocks[0].succ.contains(&0x1004));
        let ret_block = blocks.iter().find(|b| b.start == 0x1008).unwrap();
        assert!(ret_block.succ.is_empty());
    }

    #[test]
    fn straight_line_is_one_block() {
        let insns = vec![
            decode(0xD2800020, 0x1000),
            decode(0x91000400, 0x1004),
            decode(0xD65F03C0, 0x1008),
        ];
        let blocks = build_blocks(&insns);
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].insns.len(), 3);
        assert!(blocks[0].succ.is_empty());
    }
}
