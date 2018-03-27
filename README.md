# ezio

'ezio' is a file archiver with modern cipher and compression.


## Supported features:

- **Afio like archiving** : each file is compressed and encrypted individually
- **Monolithic** : no external tools required, such as gpg/openssl
- **Metadata encryption** : filename, size, and so on
- **Authenticated encryption** : AES256-GCM, CHACHA20-POLY1305
- **Public-key encryption** : RSA key/certification
- **Electronic signature** : RSA, ECDSA key/certification
- **Modern compression** : zstd(default), lz4, xz, bzip2
- **Erasure code** : aka recovery record, repairing damaged archive
- **Metadata list** : quick access to file list in the archive
- **Extended Attribute** : SElinux, capability, ACL
- **Easy to enhance** : Go!
- **Easy to use** : it's ez.


## Status

- Linux: fully supported
- FreeBSD: Extended Attribute not supported yet
- Windows: regular file and directory only. not fully tested


## Todo

- Windows support
- zstd compression with dictionary
- speed and memory optimization
- better messages and error handling


## Archive: ezio -a

### basic usage

<dl>

<dt>tar style:</dt>
<dd><strong><code>ezio -af archive.aez srcdir</strong></code></dd>

<dt>afio style:</dt>
<dd><strong><code>find srcdir -print | ezio -a -f archive.aez</code></strong></dd>

<dt>filter style:</dt>
<dd><strong><code>find srcdir -print | ezio -a -c > archive.aez</code></strong></dd>

</dl>

### typical usage

<dl>

<dt>compress:</dt>
<dd><strong><code>ezio -azf archive.aez srcdir srcdir2 file file2</code></strong></dd>

<dt>compress and encrypt:</dt>
<dd><strong><code>ezio -aez -f archive.aez srcdir</code></strong></dd>

<dt>append metadata list and erasurecode:</dt>
<dd><strong><code>ezio -azmr -f archive.aez srcdir</code></strong></dd>

</dl>

### advanced usage

<dl>

<dt>skip non-accessible files (to be accurate, ignore all errors</dt>
<dd><strong><code>ezio -az --ignore-error -f archive.aez srcdir</code></strong></dd>

<dt>xz -9 compress:</dt>
<dd><strong><code>ezio -az -Zx -G9 -f archive.aez srcdir</code></strong></dd>

<dt>password file redirection(read all as pass, including LF and other non-ascii characters):</dt>
<dd><strong><code>ezio -ae -f archive.aez --pass-fd=3 srcdir <3 pass.txt</code></strong></dd>

<dt>public-key encryption:</dt>
<dd><strong><code>ezio -ae -f archive.aez --encrypt-key=pubkey.pem srcdir</code></strong></dd>

<dt>signature:</dt>
<dd><strong><code>ezio -aez -H5 -f archive.aez --sign-key=privkey.pem srcdir</code></strong></dd>

<dt>too many options:</dt>
<dd><strong><code>ezio -aezmrUW -f archive.aez -Zz -G11 -Ec -H5 --ignore-error --block-size=512 --block-data=64 --block-parity=3 --encrypt-key=cert.pem --sign-key=private.pem --sign-pass-file=pass.txt --exclude="bar/foo\.mp4$" --include="\.mp4$" srcdir</code></strong></dd>

</dl>

## Extract: ezio -x

### basic usage

<dl>

<dt>tar style(extract to current dir):</dt>
<dd><strong><code>ezio -xf archive.aez</code></strong></dd>

<dt>zip style:</dt>
<dd><strong><code>ezio -x -f archive.aez -d dstdir</code></strong></dd>

<dt>pipe style:</dt>
<dd><strong><code>cat archive.aez | ezio -x -d dstdir</code></strong></dd>

<dt>filter style (without -p, extract only the first file):</dt>
<dd><strong><code>cat archive.aez | ezio -x -c > dstfile</code></strong></dd>

</dl>

### advanced usage

<dl>

<dt>extract a file in the archive (ezio -l -L1 shows file position): </dt>
<dd><strong><code>ezio -x -f archive.aez -p 11345</code></strong></dd>

<dt>public-key decryption:</dt>
<dd><strong><code>ezio -x -f archive.aez --decrypt-key=prvkey.pem -d dstdir</code></strong></dd>

<dt>suppress warning:</dt>
<dd><strong><code>ezio -x -O3 -f archive.aez</code></strong></dd>

<dt>selective extract(regexp matching):</dt>
<dd><strong><code>ezio -x -f archive.aez --include-"(foo|bar)\.dat"</code></strong></dd>

</dl>

## List: ezio -l

<dl>

If metadata list exists, ezio uses it.

<dt>path only:</dt>
<dd><strong><code>ezio -l -L0 -f archive.aez</code></strong></dd>

<dt>position and path:</dt>
<dd><strong><code>ezio -l -L1 -f archive.aez</code></strong></dd>

<dt>ls -l style:</dt>
<dd><strong><code>ezio -l -L2 -f archive.aez</code></strong></dd>

<dt>encrypted archive:</dt>
<dd><strong><code>ezio -l -f archive.aez --pass-file=pass.txt</code></strong></dd>

</dl>

## View: ezio -v

<dl>

Ezio scans archive from the beginning, does not use metadata list.

<dt>stat style:</dt>
<dd> <strong><code>ezio -v -L3 -f archive.aez</code></strong></dd>

<dt>json style:</dt>
<dd> <strong><code>ezio -v -L4 -f archive.aez</code></strong></dd>

</dl>


## Test: ezio -t

<dl>

<dt>extract to /dev/null:</dt>
<dd><strong><code>ezio -t -O6 -otest.log -f archive.aez</code></strong></dd>

<dt>verify signature:</dt>
<dd><strong><code>ezio -t -f archive.aez --verify-key=cert.pem</code></strong></dd>

<dt>repair if erasure code exists(generate archive.aez.rep):</dt>
<dd><strong><code>ezio -t -r -f archive.aez</code></strong></dd>

</dl>


## Compression algorithm

**zstd -3**: better size than gzip. much faster.

**zstd -9..-11**: good size. fast.

**zstd -19**: near to bzip2 -9 size, but slow compression.

**lz4** : quite fast.

**xz -9** : best compression rate, but extremely slow compression.

**xz -1 .. -3** : good balance between size and speed.

**bzip2 -9** : good size. accpetable speed.


### sample comparison

``centos7# ezio -az -Z? -G? -f usr.aez /usr``

| method | compress(sec) | extract | size |
|:---|---|:---:|---:|
| lz4 | 36.4 | 26.1 | 938462472 |
| xz -1 | 263.5 | 83.2 | 622824297 |
| xz -9 | 1449.9 | 94.2 | 582330416 |
| bzip -9 | 446.8 | 133.1 | 720979342 |
| zstd -3 (default) | 52.1 | 39.8 | 705216234 |
| zstd -9 | 132.2 | 37.6 | 666123750 |
| zstd -11 | 228.1 | 37.4 | 661068783 |
| zstd -19 | 713.3 | 37.9 | 618484768 |


## Encryption algorithm

If your CPU has AES accelarater, AES256-GCM is faster a bit.



## Erasure Code

Ezio uses Reed-Solomon algorithm. You can specify 3 parameters: --block-size, --block-data, --block-parity.

RAID6 is a good analogy. Assume you have a big disk array consists of 130 HDDs, 128 data disks and 2 parity disks. Each HDD has capacity of 4096Bytes, so total size is 512kiB. This disk array is recoverable if 1 or 2 HDDs are damaged. That is, --block-size=4096 --block-data=128 --block-parity=2.

If archive size is over 512kiB, there are other disk arrays. Note that the parity disks in the first disk array are not useful for repairing the other disk array.
