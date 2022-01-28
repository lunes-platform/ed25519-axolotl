// Curve25519 signatures (and also key agreement)
// like in the early Axolotl.
//
// Ported to Rust by Miguel Sandro Lucero. miguel.sandro@gmail.com. 2021.09.11
// You can use it under MIT or CC0 license.
//
// Curve25519 signatures idea and math by Trevor Perrin
// https://moderncrypto.org/mail-archive/curves/2014/000205.html
//
// Derived from axlsign.js written by Dmitry Chestnykh. https://github.com/wavesplatform/curve25519-js

use rand::Rng; // 0.8.0

fn gf() -> Vec<i64> {
    let mut r: Vec<i64> = vec![0; 16];
    r
}

const _9: [u32; 32] = [
    0x9, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
];

const gf0: [i64; 16] = [
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
];

const gf1: [i64; 16] = [
    1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
];

const _121665: [i64; 16] = [
    0xdb41, 1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
];

const D: [i64; 16] = [
    0x78a3, 0x1359, 0x4dca, 0x75eb, 0xd8ab, 0x4141, 0x0a4d, 0x0070, 0xe898, 0x7779, 0x4079, 0x8cc7,
    0xfe73, 0x2b6f, 0x6cee, 0x5203,
];

const D2: [i64; 16] = [
    0xf159, 0x26b2, 0x9b94, 0xebd6, 0xb156, 0x8283, 0x149a, 0x00e0, 0xd130, 0xeef3, 0x80f2, 0x198e,
    0xfce7, 0x56df, 0xd9dc, 0x2406,
];

const X: [i64; 16] = [
    0xd51a, 0x8f25, 0x2d60, 0xc956, 0xa7b2, 0x9525, 0xc760, 0x692c, 0xdc5c, 0xfdd6, 0xe231, 0xc0a4,
    0x53fe, 0xcd6e, 0x36d3, 0x2169,
];

const Y: [i64; 16] = [
    0x6658, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666,
    0x6666, 0x6666, 0x6666, 0x6666,
];

const I: [i64; 16] = [
    0xa0b0, 0x4a0e, 0x1b27, 0xc4ee, 0xe478, 0xad2f, 0x1806, 0x2f43, 0xd7a7, 0x3dfb, 0x0099, 0x2b4d,
    0xdf0b, 0x4fc1, 0x2480, 0x2b83,
];

fn ts64(x: &mut Vec<u32>, i: usize, h: u32, l: u32) {
    x[i] = (h >> 24) & 0xff;
    x[i + 1] = (h >> 16) & 0xff;
    x[i + 2] = (h >> 8) & 0xff;
    x[i + 3] = h & 0xff;
    x[i + 4] = (l >> 24) & 0xff;
    x[i + 5] = (l >> 16) & 0xff;
    x[i + 6] = (l >> 8) & 0xff;
    x[i + 7] = l & 0xff;
}

fn vn(x: &Vec<u32>, xi: usize, y: &Vec<u32>, yi: usize, n: usize) -> isize {
    let mut d: u32 = 0;
    for i in 1..n {
        d = d | (x[xi + i] ^ y[yi + i]);
    }
    let _d: i32 = d as i32 - 1;
    let _r = (1 & (_d as u32 >> 8)) as i32 - 1;
    return _r as isize;
}

fn crypto_verify_32(x: &Vec<u32>, xi: usize, y: &Vec<u32>, yi: usize) -> isize {
    return vn(x, xi, y, yi, 32);
}

fn set25519(r: &mut Vec<i64>, a: &Vec<i64>) {
    for i in 0..16 {
        r[i] = a[i] | 0;
    }
}

fn car25519(o: &mut Vec<i64>) {
    let mut v: i64;
    let mut c: i64 = 1;
    for i in 0..16 {
        v = o[i] + c + 65535;
        c = v / 65536;
        o[i] = v - c * 65536;
    }
    o[0] += c - 1 + 37 * (c - 1);
}

fn sel25519(p: &mut Vec<i64>, q: &mut Vec<i64>, b: isize) {
    let mut t: i64;
    let c: i64 = (!(b - 1)) as i64;
    for i in 0..16 {
        t = c & (p[i] ^ q[i]);
        p[i] = p[i] ^ t;
        q[i] = q[i] ^ t;
    }
}

fn pack25519(o: &mut Vec<u32>, n: &Vec<i64>) {
    let mut b: i64;
    let mut m = gf();
    let mut t = gf();

    for i in 0..16 {
        t[i] = n[i];
    }
    car25519(&mut t);
    car25519(&mut t);
    car25519(&mut t);

    for j in 0..2 {
        m[0] = t[0] - 0xffed;
        for i in 1..15 {
            m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
            m[i - 1] = m[i - 1] & 0xffff;
        }
        m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
        b = (m[15] >> 16) & 1;
        m[14] = m[14] & 0xffff;
        sel25519(&mut t, &mut m, 1 - b as isize);
    }

    for i in 0..16 {
        o[2 * i] = (t[i] & 0xff) as u32;
        o[2 * i + 1] = (t[i] >> 8) as u32;
    }
}

fn neq25519(a: &Vec<i64>, b: &Vec<i64>) -> isize {
    let mut c: Vec<u32> = vec![0; 32];
    let mut d: Vec<u32> = vec![0; 32];
    pack25519(&mut c, a);
    pack25519(&mut d, b);
    return crypto_verify_32(&c, 0, &d, 0);
}

fn par25519(a: &Vec<i64>) -> u32 {
    let mut d: Vec<u32> = vec![0; 32];
    pack25519(&mut d, a);
    return d[0] & 1;
}

fn unpack25519(o: &mut Vec<i64>, n: &Vec<u32>) {
    for i in 0..16 {
        let value: u32 = n[2 * i] + (n[2 * i + 1] << 8);
        o[i] = value as i64;
    }
    o[15] = o[15] & 0x7fff;
}

fn A(o: &mut Vec<i64>, a: &Vec<i64>, b: &Vec<i64>) {
    for i in 0..16 {
        o[i] = a[i] + b[i];
    }
}

fn Z(o: &mut Vec<i64>, a: &Vec<i64>, b: &Vec<i64>) {
    for i in 0..16 {
        o[i] = a[i] - b[i];
    }
}

// optimized by Miguel
fn M(o: &mut Vec<i64>, a: &Vec<i64>, b: &Vec<i64>) {
    let mut at: Vec<i64> = vec![0; 32];
    let mut ab: Vec<i64> = vec![0; 16];

    for i in 0..16 {
        ab[i] = b[i];
    }

    let mut v: i64;
    for i in 0..16 {
        v = a[i];
        for j in 0..16 {
            at[j + i] += v * ab[j];
        }
    }

    for i in 0..15 {
        at[i] += 38 * at[i + 16];
    }
    // t15 left as is

    // first car
    let mut c: i64 = 1;
    for i in 0..16 {
        v = at[i] + c + 65535;
        c = (v as f64 / 65536.0).floor() as i64;
        at[i] = v - c * 65536;
    }
    at[0] += c - 1 + 37 * (c - 1);

    // second car
    c = 1;
    for i in 0..16 {
        v = at[i] + c + 65535;
        c = (v as f64 / 65536.0).floor() as i64;
        at[i] = v - c * 65536;
    }
    at[0] += c - 1 + 37 * (c - 1);

    for i in 0..16 {
        o[i] = at[i];
    }
}

fn S(o: &mut Vec<i64>, a: &Vec<i64>) {
    M(o, &a, &a);
}

fn inv25519(o: &mut Vec<i64>, i: &Vec<i64>) {
    let mut c = gf();
    for a in 0..16 {
        c[a] = i[a];
    }

    for a in (0..=253).rev() {
        let cc = c.clone();
        S(&mut c, &cc);
        if a != 2 && a != 4 {
            let cc = c.clone();
            M(&mut c, &cc, i);
        }
    }
    for a in 0..16 {
        o[a] = c[a];
    }
}

fn pow2523(o: &mut Vec<i64>, i: &Vec<i64>) {
    let mut c = gf();
    for a in 0..16 {
        c[a] = i[a];
    }
    for a in (0..=250).rev() {
        let cc = c.clone();
        S(&mut c, &cc);
        if a != 1 {
            let cc = c.clone();
            M(&mut c, &cc, &i);
        }
    }
    for a in 0..16 {
        o[a] = c[a];
    }
}

fn crypto_scalarmult(q: &mut Vec<u32>, n: &Vec<u32>, p: &Vec<u32>) -> usize {
    let mut z: Vec<u32> = vec![0; 32];
    let mut x: Vec<i64> = vec![0; 80];
    let mut r: u32;

    let mut a = gf();
    let mut b = gf();
    let mut c = gf();
    let mut d = gf();
    let mut e = gf();
    let mut f = gf();

    for i in 0..31 {
        z[i] = n[i];
    }
    z[31] = (n[31] & 127) | 64;
    z[0] = z[0] & 248;

    unpack25519(&mut x, p);

    for i in 0..16 {
        b[i] = x[i];
        d[i] = 0;
        a[i] = 0;
        c[i] = 0;
    }
    a[0] = 1;
    d[0] = 1;

    for i in (0..=254).rev() {
        r = (z[i >> 3] >> (i & 7)) & 1; // *** R r=(z[i>>>3]>>>(i&7))&1;

        sel25519(&mut a, &mut b, r as isize);
        sel25519(&mut c, &mut d, r as isize);
        A(&mut e, &a, &c);
        let aa = a.clone();
        Z(&mut a, &aa, &c);
        A(&mut c, &b, &d);
        let bb = b.clone();
        Z(&mut b, &bb, &d);
        S(&mut d, &e);
        S(&mut f, &a);
        let aa = a.clone();
        M(&mut a, &c, &aa);
        M(&mut c, &b, &e);
        A(&mut e, &a, &c);
        let aa = a.clone();
        Z(&mut a, &aa, &c);
        S(&mut b, &a);
        Z(&mut c, &d, &f);
        M(&mut a, &c, &_121665.to_vec());
        let aa = a.clone();
        A(&mut a, &aa, &d);
        let cc = c.clone();
        M(&mut c, &cc, &a);
        M(&mut a, &d, &f);
        M(&mut d, &b, &x);
        S(&mut b, &e);
        sel25519(&mut a, &mut b, r as isize);
        sel25519(&mut c, &mut d, r as isize);
    }

    for i in 0..16 {
        x[i + 16] = a[i];
        x[i + 32] = c[i];
        x[i + 48] = b[i];
        x[i + 64] = d[i];
    }

    let mut x32: Vec<i64> = (&x[32..]).to_vec();
    let mut x16: Vec<i64> = (&x[16..]).to_vec();

    let xx32 = x32.clone();
    inv25519(&mut x32, &xx32);
    let xx16 = x16.clone();
    M(&mut x16, &xx16, &x32);

    pack25519(q, &x16);

    return 0;
}

// Constantes de cada ronda del SHA-512
const K: [i64; 160] = [
    0x428a2f98, 0xd728ae22, 0x71374491, 0x23ef65cd, 0xb5c0fbcf, 0xec4d3b2f, 0xe9b5dba5, 0x8189dbbc,
    0x3956c25b, 0xf348b538, 0x59f111f1, 0xb605d019, 0x923f82a4, 0xaf194f9b, 0xab1c5ed5, 0xda6d8118,
    0xd807aa98, 0xa3030242, 0x12835b01, 0x45706fbe, 0x243185be, 0x4ee4b28c, 0x550c7dc3, 0xd5ffb4e2,
    0x72be5d74, 0xf27b896f, 0x80deb1fe, 0x3b1696b1, 0x9bdc06a7, 0x25c71235, 0xc19bf174, 0xcf692694,
    0xe49b69c1, 0x9ef14ad2, 0xefbe4786, 0x384f25e3, 0x0fc19dc6, 0x8b8cd5b5, 0x240ca1cc, 0x77ac9c65,
    0x2de92c6f, 0x592b0275, 0x4a7484aa, 0x6ea6e483, 0x5cb0a9dc, 0xbd41fbd4, 0x76f988da, 0x831153b5,
    0x983e5152, 0xee66dfab, 0xa831c66d, 0x2db43210, 0xb00327c8, 0x98fb213f, 0xbf597fc7, 0xbeef0ee4,
    0xc6e00bf3, 0x3da88fc2, 0xd5a79147, 0x930aa725, 0x06ca6351, 0xe003826f, 0x14292967, 0x0a0e6e70,
    0x27b70a85, 0x46d22ffc, 0x2e1b2138, 0x5c26c926, 0x4d2c6dfc, 0x5ac42aed, 0x53380d13, 0x9d95b3df,
    0x650a7354, 0x8baf63de, 0x766a0abb, 0x3c77b2a8, 0x81c2c92e, 0x47edaee6, 0x92722c85, 0x1482353b,
    0xa2bfe8a1, 0x4cf10364, 0xa81a664b, 0xbc423001, 0xc24b8b70, 0xd0f89791, 0xc76c51a3, 0x0654be30,
    0xd192e819, 0xd6ef5218, 0xd6990624, 0x5565a910, 0xf40e3585, 0x5771202a, 0x106aa070, 0x32bbd1b8,
    0x19a4c116, 0xb8d2d0c8, 0x1e376c08, 0x5141ab53, 0x2748774c, 0xdf8eeb99, 0x34b0bcb5, 0xe19b48a8,
    0x391c0cb3, 0xc5c95a63, 0x4ed8aa4a, 0xe3418acb, 0x5b9cca4f, 0x7763e373, 0x682e6ff3, 0xd6b2b8a3,
    0x748f82ee, 0x5defb2fc, 0x78a5636f, 0x43172f60, 0x84c87814, 0xa1f0ab72, 0x8cc70208, 0x1a6439ec,
    0x90befffa, 0x23631e28, 0xa4506ceb, 0xde82bde9, 0xbef9a3f7, 0xb2c67915, 0xc67178f2, 0xe372532b,
    0xca273ece, 0xea26619c, 0xd186b8c7, 0x21c0c207, 0xeada7dd6, 0xcde0eb1e, 0xf57d4f7f, 0xee6ed178,
    0x06f067aa, 0x72176fba, 0x0a637dc5, 0xa2c898a6, 0x113f9804, 0xbef90dae, 0x1b710b35, 0x131c471b,
    0x28db77f5, 0x23047d84, 0x32caab7b, 0x40c72493, 0x3c9ebe0a, 0x15c9bebc, 0x431d67c4, 0x9c100d4c,
    0x4cc5d4be, 0xcb3e42b6, 0x597f299c, 0xfc657e2a, 0x5fcb6fab, 0x3ad6faec, 0x6c44198c, 0x4a475817,
];

// optimized by miguel
fn crypto_hashblocks_hl(hh: &mut Vec<u32>, hl: &mut Vec<u32>, m: &Vec<u32>, _n: usize) -> usize {
    let mut wh: Vec<u32> = vec![0; 16];
    let mut wl: Vec<u32> = vec![0; 16];

    let mut bh: Vec<u32> = vec![0; 8];
    let mut bl: Vec<u32> = vec![0; 8];

    let mut th: u32;
    let mut tl: u32;
    let mut h: u32;
    let mut l: u32;
    let mut a: u32;
    let mut b: u32;
    let mut c: u32;
    let mut d: u32;

    let mut ah: Vec<u32> = vec![0; 8];
    let mut al: Vec<u32> = vec![0; 8];

    for i in 0..8 {
        ah[i] = hh[i];
        al[i] = hl[i];
    }

    let mut pos = 0;
    let mut n = _n;
    while n >= 128 {
        for i in 0..16 {
            let j = 8 * i + pos;
            wh[i] = (m[j + 0] << 24) | (m[j + 1] << 16) | (m[j + 2] << 8) | m[j + 3];
            wl[i] = (m[j + 4] << 24) | (m[j + 5] << 16) | (m[j + 6] << 8) | m[j + 7];
        }

        for i in 0..80 {
            for j in 0..7 {
                bh[j] = ah[j];
                bl[j] = al[j];
            }

            // add
            h = ah[7];
            l = al[7];

            a = l & 0xffff;
            b = l as u32 >> 16;
            c = h & 0xffff;
            d = h as u32 >> 16;

            // Sigma1
            h = ((ah[4] as u32 >> 14) | (al[4] << (32 - 14)))
                ^ ((ah[4] as u32 >> 18) | (al[4] << (32 - 18)))
                ^ ((al[4] as u32 >> (41 - 32)) | (ah[4] << (32 - (41 - 32))));
            l = ((al[4] as u32 >> 14) | (ah[4] << (32 - 14)))
                ^ ((al[4] as u32 >> 18) | (ah[4] << (32 - 18)))
                ^ ((ah[4] as u32 >> (41 - 32)) | (al[4] << (32 - (41 - 32))));

            a += l & 0xffff;
            b += l as u32 >> 16;
            c += h & 0xffff;
            d += h as u32 >> 16;

            // Ch
            h = (ah[4] & ah[5]) ^ (!ah[4] & ah[6]);
            l = (al[4] & al[5]) ^ (!al[4] & al[6]);

            a += l & 0xffff;
            b += l as u32 >> 16;
            c += h & 0xffff;
            d += h as u32 >> 16;

            // K
            h = K[i * 2] as u32;
            l = K[i * 2 + 1] as u32;

            a += l & 0xffff;
            b += l as u32 >> 16;
            c += h & 0xffff;
            d += h as u32 >> 16;

            // w
            h = wh[i % 16];
            l = wl[i % 16];

            a += l & 0xffff;
            b += l as u32 >> 16;
            c += h & 0xffff;
            d += h as u32 >> 16;

            b += a as u32 >> 16;
            c += b as u32 >> 16;
            d += c as u32 >> 16;

            // *** R
            th = c & 0xffff | (d << 16);
            tl = a & 0xffff | (b << 16);

            // add
            h = th;
            l = tl;

            a = l & 0xffff;
            b = l as u32 >> 16;
            c = h & 0xffff;
            d = h as u32 >> 16;

            // Sigma0
            h = ((ah[0] as u32 >> 28) | (al[0] << (32 - 28)))
                ^ ((al[0] as u32 >> (34 - 32)) | (ah[0] << (32 - (34 - 32))))
                ^ ((al[0] as u32 >> (39 - 32)) | (ah[0] << (32 - (39 - 32))));
            l = ((al[0] as u32 >> 28) | (ah[0] << (32 - 28)))
                ^ ((ah[0] as u32 >> (34 - 32)) | (al[0] << (32 - (34 - 32))))
                ^ ((ah[0] as u32 >> (39 - 32)) | (al[0] << (32 - (39 - 32))));

            a += l & 0xffff;
            b += l as u32 >> 16;
            c += h & 0xffff;
            d += h as u32 >> 16;

            // Maj
            h = (ah[0] & ah[1]) ^ (ah[0] & ah[2]) ^ (ah[1] & ah[2]);
            l = (al[0] & al[1]) ^ (al[0] & al[2]) ^ (al[1] & al[2]);

            a += l & 0xffff;
            b += l as u32 >> 16;
            c += h & 0xffff;
            d += h as u32 >> 16;

            b += a as u32 >> 16;
            c += b as u32 >> 16;
            d += c as u32 >> 16;

            bh[7] = (c & 0xffff) | (d << 16);
            bl[7] = (a & 0xffff) | (b << 16);

            // add
            h = bh[3];
            l = bl[3];

            a = l & 0xffff;
            b = l as u32 >> 16;
            c = h & 0xffff;
            d = h as u32 >> 16;

            h = th;
            l = tl;

            a += l & 0xffff;
            b += l as u32 >> 16;
            c += h & 0xffff;
            d += h as u32 >> 16;

            b += a as u32 >> 16;
            c += b as u32 >> 16;
            d += c as u32 >> 16;

            bh[3] = (c & 0xffff) | (d << 16);
            bl[3] = (a & 0xffff) | (b << 16);

            for j in 0..8 {
                let k = (j + 1) % 8;
                ah[k] = bh[j];
                al[k] = bl[j];
            }

            if i % 16 == 15 {
                for j in 0..16 {
                    // add
                    h = wh[j];
                    l = wl[j];

                    a = l & 0xffff;
                    b = l as u32 >> 16;
                    c = h & 0xffff;
                    d = h as u32 >> 16;

                    h = wh[(j + 9) % 16];
                    l = wl[(j + 9) % 16];

                    a += l & 0xffff;
                    b += l as u32 >> 16;
                    c += h & 0xffff;
                    d += h as u32 >> 16;

                    // sigma0
                    th = wh[(j + 1) % 16];
                    tl = wl[(j + 1) % 16];

                    h = ((th as u32 >> 1) | (tl << (32 - 1)))
                        ^ ((th as u32 >> 8) | (tl << (32 - 8)))
                        ^ (th as u32 >> 7);
                    l = ((tl as u32 >> 1) | (th << (32 - 1)))
                        ^ ((tl as u32 >> 8) | (th << (32 - 8)))
                        ^ ((tl as u32 >> 7) | (th << (32 - 7)));

                    a += l & 0xffff;
                    b += l as u32 >> 16;
                    c += h & 0xffff;
                    d += h as u32 >> 16;

                    // sigma1
                    th = wh[(j + 14) % 16];
                    tl = wl[(j + 14) % 16];

                    h = ((th as u32 >> 19) | (tl << (32 - 19)))
                        ^ ((tl as u32 >> (61 - 32)) | (th << (32 - (61 - 32))))
                        ^ (th as u32 >> 6);
                    l = ((tl as u32 >> 19) | (th << (32 - 19)))
                        ^ ((th as u32 >> (61 - 32)) | (tl << (32 - (61 - 32))))
                        ^ ((tl as u32 >> 6) | (th << (32 - 6)));

                    a += l & 0xffff;
                    b += l as u32 >> 16;
                    c += h & 0xffff;
                    d += h as u32 >> 16;

                    b += a as u32 >> 16;
                    c += b as u32 >> 16;
                    d += c as u32 >> 16;

                    wh[j] = (c & 0xffff) | (d << 16);
                    wl[j] = (a & 0xffff) | (b << 16);
                }
            }
        }

        // add
        a = 0;
        b = 0;
        c = 0;
        d = 0;
        for k in 0..8 {
            if k == 0 {
                h = ah[0];
                l = al[0];
                a = l & 0xffff;
                b = l as u32 >> 16;
                c = h & 0xffff;
                d = h as u32 >> 16;
            }

            h = hh[k];
            l = hl[k];

            a += l & 0xffff;
            b += l as u32 >> 16;
            c += h & 0xffff;
            d += h as u32 >> 16;

            b += a as u32 >> 16;
            c += b as u32 >> 16;
            d += c as u32 >> 16;

            hh[k] = (c & 0xffff) | (d << 16);
            ah[k] = (c & 0xffff) | (d << 16);

            hl[k] = (a & 0xffff) | (b << 16);
            al[k] = (a & 0xffff) | (b << 16);

            if k < 7 {
                h = ah[k + 1];
                l = al[k + 1];

                a = l & 0xffff;
                b = l as u32 >> 16;
                c = h & 0xffff;
                d = h as u32 >> 16;
            }
        }

        pos += 128;
        n -= 128;
    }

    return n;
}

fn crypto_hash(out: &mut Vec<u32>, m: &Vec<u32>, _n: usize) -> usize {
    let mut hh: Vec<u32> = ([
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ])
    .to_vec();
    let mut hl: Vec<u32> = ([
        0xf3bcc908, 0x84caa73b, 0xfe94f82b, 0x5f1d36f1, 0xade682d1, 0x2b3e6c1f, 0xfb41bd6b,
        0x137e2179,
    ])
    .to_vec();
    let mut x: Vec<u32> = vec![0; 256];
    let mut n = _n;
    let b = n;

    crypto_hashblocks_hl(&mut hh, &mut hl, &m, n);

    n %= 128;

    for i in 0..n {
        x[i] = m[b - n + i];
    }
    x[n] = 128;

    if n < 112 {
        n = 256 - 128 * 1;
    } else {
        n = 256 - 128 * 0;
    }
    x[n - 9] = 0;

    ts64(
        &mut x,
        n - 8,
        ((b / 0x20000000) | 0) as u32,
        (b << 3) as u32,
    );

    crypto_hashblocks_hl(&mut hh, &mut hl, &x, n);

    for i in 0..8 {
        ts64(out, 8 * i, hh[i], hl[i]);
    }

    return 0;
}

fn add(p: &mut Vec<Vec<i64>>, q: &mut Vec<Vec<i64>>) {
    let mut a = gf();
    let mut b = gf();
    let mut c = gf();
    let mut d = gf();
    let mut e = gf();
    let mut f = gf();
    let mut g = gf();
    let mut h = gf();
    let mut t = gf();

    Z(&mut a, &p[1], &p[0]);
    Z(&mut t, &q[1], &q[0]);
    let aa = a.clone();
    M(&mut a, &aa, &t);
    A(&mut b, &p[0], &p[1]);
    A(&mut t, &q[0], &q[1]);
    let bb = b.clone();
    M(&mut b, &bb, &t);
    M(&mut c, &p[3], &q[3]);
    let cc = c.clone();
    M(&mut c, &cc, &D2.to_vec());
    M(&mut d, &p[2], &q[2]);
    let dd = d.clone();
    A(&mut d, &dd, &dd);
    Z(&mut e, &b, &a);
    Z(&mut f, &d, &c);
    A(&mut g, &d, &c);
    A(&mut h, &b, &a);

    M(&mut p[0], &e, &f);
    M(&mut p[1], &h, &g);
    M(&mut p[2], &g, &f);
    M(&mut p[3], &e, &h);
}

fn cswap(p: &mut Vec<Vec<i64>>, q: &mut Vec<Vec<i64>>, b: isize) {
    for i in 0..4 {
        sel25519(&mut p[i], &mut q[i], b)
    }
}

fn pack(r: &mut Vec<u32>, p: &Vec<Vec<i64>>) {
    let mut tx = gf();
    let mut ty = gf();
    let mut zi = gf();

    inv25519(&mut zi, &p[2]);

    M(&mut tx, &p[0], &zi);
    M(&mut ty, &p[1], &zi);

    pack25519(r, &ty);

    r[31] = r[31] ^ (par25519(&tx) << 7)
}

fn scalarmult(p: &mut Vec<Vec<i64>>, q: &mut Vec<Vec<i64>>, s: &Vec<u32>) {
    let mut b: u32;

    set25519(&mut p[0], &gf0.to_vec());
    set25519(&mut p[1], &gf1.to_vec());
    set25519(&mut p[2], &gf1.to_vec());
    set25519(&mut p[3], &gf0.to_vec());

    for i in (0..=255).rev() {
        b = (s[(i / 8) | 0] >> (i & 7)) & 1;
        cswap(p, q, b as isize);
        add(q, p);
        let mut pp = p.clone();
        add(p, &mut pp);
        cswap(p, q, b as isize);
    }
}

fn scalarbase(p: &mut Vec<Vec<i64>>, s: &Vec<u32>) {
    let mut q: Vec<Vec<i64>> = ([gf(), gf(), gf(), gf()]).to_vec();
    set25519(&mut q[0], &X.to_vec());
    set25519(&mut q[1], &Y.to_vec());
    set25519(&mut q[2], &gf1.to_vec());
    M(&mut q[3], &X.to_vec(), &Y.to_vec());
    scalarmult(p, &mut q, s);
}

const L: [i32; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
];

fn mod_l(r: &mut Vec<u32>, x: &mut Vec<i32>) {
    let mut carry: i32;

    for i in (32..=63).rev() {
        carry = 0;
        let mut j = i - 32;
        let k = i - 12;
        while j < k {
            x[j] += carry - 16 * x[i] * L[j - (i - 32)];
            carry = (x[j] + 128) >> 8;
            x[j] -= carry * 256;
            j += 1;
        }
        x[j] += carry;
        x[i] = 0;
    }

    carry = 0;
    for j in 0..32 {
        x[j] += carry - (x[31] >> 4) * L[j];
        carry = x[j] >> 8;
        x[j] = x[j] & 255;
    }

    for j in 0..32 {
        x[j] -= carry * L[j];
    }

    for i in 0..32 {
        x[i + 1] += x[i] >> 8;
        r[i] = (x[i] & 255) as u32;
    }
}

fn reduce(r: &mut Vec<u32>) {
    let mut x: Vec<i32> = vec![0; 64];
    for i in 0..64 {
        x[i] = r[i] as i32;
    }
    for i in 0..64 {
        r[i] = 0;
    }
    mod_l(r, &mut x);
}

// Like crypto_sign, but uses secret key directly in hash.
fn crypto_sign_direct(sm: &mut Vec<u32>, m: &Vec<u32>, n: usize, sk: &Vec<u32>) -> usize {
    let mut h: Vec<u32> = vec![0; 64];
    let mut r: Vec<u32> = vec![0; 64];
    let mut x: Vec<i32> = vec![0; 64];
    let mut p: Vec<Vec<i64>> = ([gf(), gf(), gf(), gf()]).to_vec();

    for i in 0..n {
        sm[64 + i] = m[i];
    }

    for i in 0..32 {
        sm[32 + i] = sk[i];
    }

    let mut x32: Vec<u32> = (&sm[32..]).to_vec();

    crypto_hash(&mut r, &x32, n + 32);

    reduce(&mut r);

    scalarbase(&mut p, &r);

    pack(sm, &p);

    for i in 0..32 {
        sm[i + 32] = sk[32 + i];
    }

    crypto_hash(&mut h, &sm, n + 64);
    reduce(&mut h);

    for i in 0..64 {
        x[i] = 0;
    }

    for i in 0..32 {
        x[i] = r[i] as i32;
    }

    for i in 0..32 {
        for j in 0..32 {
            x[i + j] += (h[i] * sk[j]) as i32;
        }
    }

    let mut tmp: Vec<u32> = (&sm[32..]).to_vec();
    mod_l(&mut tmp, &mut x);
    for i in 0..tmp.len() {
        sm[32 + i] = tmp[i];
    }

    return n + 64;
}

// Note: sm must be n+128.
fn crypto_sign_direct_rnd(
    sm: &mut Vec<u32>,
    m: &Vec<u32>,
    n: usize,
    sk: &Vec<u32>,
    rnd: &Vec<u32>,
) -> usize {
    let mut h: Vec<u32> = vec![0; 64];
    let mut r: Vec<u32> = vec![0; 64];
    let mut x: Vec<i32> = vec![0; 64];
    let mut p: Vec<Vec<i64>> = ([gf(), gf(), gf(), gf()]).to_vec();

    // Hash separation.
    sm[0] = 0xfe;
    for i in 1..32 {
        sm[i] = 0xff;
    }

    // Secret key.
    for i in 0..32 {
        sm[32 + i] = sk[i];
    }

    // Message.
    for i in 0..n {
        sm[64 + i] = m[i];
    }

    // Random suffix.
    for i in 0..64 {
        sm[n + 64 + i] = rnd[i];
    }

    crypto_hash(&mut r, &sm, n + 128);
    reduce(&mut r);
    scalarbase(&mut p, &r);
    pack(sm, &p);

    for i in 0..32 {
        sm[i + 32] = sk[32 + i];
    }

    crypto_hash(&mut h, &sm, n + 64);
    reduce(&mut h);

    // Wipe out random suffix.
    for i in 0..64 {
        sm[n + 64 + i] = 0;
    }

    for i in 0..64 {
        x[i] = 0;
    }

    for i in 0..32 {
        x[i] = r[i] as i32;
    }

    for i in 0..32 {
        for j in 0..32 {
            x[i + j] += (h[i] * sk[j]) as i32;
        }
    }

    let mut tmp: Vec<u32> = (&sm[32..]).to_vec();
    mod_l(&mut tmp, &mut x);
    for i in 0..tmp.len() {
        sm[32 + i] = tmp[i];
    }

    return n + 64;
}

pub fn curve25519_sign(
    sm: &mut Vec<u32>,
    m: &Vec<u32>,
    n: usize,
    sk: &Vec<u32>,
    opt_rnd: &Vec<u32>,
) -> usize {
    // If opt_rnd is provided, sm must have n + 128,
    // otherwise it must have n + 64 bytes.

    // Convert Curve25519 secret key into Ed25519 secret key (includes pub key).
    let mut edsk: Vec<u32> = vec![0; 64];
    let mut p: Vec<Vec<i64>> = ([gf(), gf(), gf(), gf()]).to_vec();

    for i in 0..32 {
        edsk[i] = sk[i];
    }

    // Ensure private key is in the correct format.
    edsk[0] = edsk[0] & 248;
    edsk[31] = edsk[31] & 127;
    edsk[31] = edsk[31] | 64;

    scalarbase(&mut p, &edsk);

    let mut tmp: Vec<u32> = (&edsk[32..]).to_vec();
    pack(&mut tmp, &p);
    for i in 0..tmp.len() {
        edsk[32 + i] = tmp[i];
    }

    // Remember sign bit.
    let sign_bit = edsk[63] & 128;
    let mut smlen: usize;

    if opt_rnd.len() > 0 {
        smlen = crypto_sign_direct_rnd(sm, m, n, &edsk, opt_rnd);
    } else {
        smlen = crypto_sign_direct(sm, m, n, &edsk);
    }

    // Copy sign bit from public key into signature.
    sm[63] = sm[63] | sign_bit;
    return smlen;
}

fn unpackneg(r: &mut Vec<Vec<i64>>, p: &Vec<u32>) -> isize {
    let mut t = gf();
    let mut chk = gf();
    let mut num = gf();
    let mut den = gf();
    let mut den2 = gf();
    let mut den4 = gf();
    let mut den6 = gf();

    set25519(&mut r[2], &gf1.to_vec());
    unpack25519(&mut r[1], &p);

    S(&mut num, &r[1]);
    M(&mut den, &num, &D.to_vec());
    let _num = num.clone();
    Z(&mut num, &_num, &r[2]);
    let _den = den.clone();
    A(&mut den, &r[2], &_den);

    S(&mut den2, &den);
    S(&mut den4, &den2);
    M(&mut den6, &den4, &den2);
    M(&mut t, &den6, &num);
    let _t = t.clone();
    M(&mut t, &_t, &den);

    let _t = t.clone();
    pow2523(&mut t, &_t);
    let _t = t.clone();
    M(&mut t, &_t, &num);
    let _t = t.clone();
    M(&mut t, &_t, &den);
    let _t = t.clone();
    M(&mut t, &_t, &den);
    M(&mut r[0], &t, &den);

    S(&mut chk, &r[0]);
    let _chk = chk.clone();
    M(&mut chk, &_chk, &den);

    if neq25519(&chk, &num) != 0 {
        let _r0 = r[0].clone();
        M(&mut r[0], &_r0, &I.to_vec());
    }

    S(&mut chk, &r[0]);
    let _chk = chk.clone();
    M(&mut chk, &_chk, &den);

    if neq25519(&chk, &num) != 0 {
        return -1;
    }

    if par25519(&r[0]) == (p[31] >> 7) {
        let _r0 = r[0].clone();
        Z(&mut r[0], &gf0.to_vec(), &_r0);
    }

    let _r0 = r[0].clone();
    let _r1 = r[1].clone();
    M(&mut r[3], &_r0, &_r1);

    return 0;
}

fn crypto_sign_open(m: &mut Vec<u32>, sm: &Vec<u32>, _n: usize, pk: &Vec<u32>) -> isize {
    let mut t: Vec<u32> = vec![0; 32];
    let mut h: Vec<u32> = vec![0; 64];
    let mut p: Vec<Vec<i64>> = ([gf(), gf(), gf(), gf()]).to_vec();
    let mut q: Vec<Vec<i64>> = ([gf(), gf(), gf(), gf()]).to_vec();
    let mut n = _n;

    let mut mlen = -1;
    if n < 64 {
        return mlen;
    }

    if unpackneg(&mut q, &pk) != 0 {
        return mlen;
    }

    for i in 0..n {
        m[i] = sm[i];
    }

    for i in 0..32 {
        m[i + 32] = pk[i];
    }

    crypto_hash(&mut h, &m, n);
    reduce(&mut h);
    scalarmult(&mut p, &mut q, &h);

    let mut tmp: Vec<u32> = (&sm[32..]).to_vec();
    scalarbase(&mut q, &tmp);
    add(&mut p, &mut q);
    pack(&mut t, &p);

    n -= 64;
    if crypto_verify_32(&sm, 0, &t, 0) != 0 {
        for i in 0..n {
            m[i] = 0;
        }
        return -1;
    }

    for i in 0..n {
        m[i] = sm[i + 64];
    }

    mlen = n as isize;
    return mlen;
}

// Converts Curve25519 public key back to Ed25519 public key.
// edwardsY = (montgomeryX - 1) / (montgomeryX + 1)
fn convert_public_key(pk: &Vec<u32>) -> Vec<u32> {
    let mut z: Vec<u32> = vec![0; 32];
    let mut x = gf();
    let mut a = gf();
    let mut b = gf();

    unpack25519(&mut x, &pk);

    A(&mut a, &x, &gf1.to_vec());
    Z(&mut b, &x, &gf1.to_vec());
    let _a = a.clone();
    inv25519(&mut a, &_a);
    let _a = a.clone();
    M(&mut a, &_a, &b);

    pack25519(&mut z, &a);
    return z;
}

pub fn curve25519_sign_open(m: &mut Vec<u32>, sm: &mut Vec<u32>, n: usize, pk: &Vec<u32>) -> isize {
    // Convert Curve25519 public key into Ed25519 public key.
    let mut edpk = convert_public_key(&pk);

    // Restore sign bit from signature.
    edpk[31] = edpk[31] | (sm[63] & 128);

    // Remove sign bit from signature.
    sm[63] = sm[63] & 127;

    // Verify signed message.
    return crypto_sign_open(m, &sm, n, &edpk);
}

fn shared_key(secret_key: &Vec<u32>, public_key: &Vec<u32>) -> Vec<u32> {
    let mut shared_key: Vec<u32> = vec![0; 32];
    crypto_scalarmult(&mut shared_key, secret_key, public_key);
    return shared_key;
}

pub fn crypto_scalarmult_base(q: &mut Vec<u32>, n: &Vec<u32>) -> usize {
    return crypto_scalarmult(q, n, &_9.to_vec());
}
