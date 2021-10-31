# hello-SM4
应用密码学课程作业

## 算法实现

SM4算法参考[GB/T 32907-2016《信息安全技术SM4 分组密码算法》](http://std.samr.gov.cn/gb/search/gbDetailed?id=71F772D81199D3A7E05397BE0A0AB82A)。

ECB模式和CTR模式的实现参考[*Cryptography and Network Security*: *Principles and Practice*](http://www.cs.vsb.cz/ochodkova/courses/kpb/cryptography-and-network-security_-principles-and-practice-7th-global-edition.pdf)相关章节。

已使用OpenSSL对算法实现进行了不全面的验证。

## 使用方法

准备好Python 3.9以上的虚拟环境，运行`pip install --editable .`，然后运行`hello-sm4 --help`显示：

```
Usage: hello-sm4 [OPTIONS] COMMAND [ARGS]...

Options:
  --help  Show this message and exit.

Commands:
  sm4-ctr
  sm4-ecb
```

### ECB模式

运行`hello-sm4 sm4-ecb --help`显示：

```
Usage: hello-sm4 sm4-ecb [OPTIONS]

Options:
  -e / -d        Encrypt/decrypt  [required]
  -in FILENAME   Input file  [required]
  -out FILENAME  Output file  [required]
  -K TEXT        Raw key, in hex  [required]
  --help         Show this message and exit.
```

加密：

```shell
hello-sm4 sm4-ecb -e -in logo.rgba -out e.rgba -K 0123456789abcdeffedcba9876543210
```

解密：

```shell
hello-sm4 sm4-ecb -d -in e.rgba -out o.rgba -K 0123456789abcdeffedcba9876543210
```

### CTR模式

CTR模式类似，但加解密时需要额外提供初始化向量`IV`的16进制值。

```shell
hello-sm4 sm4-ctr -e -in logo.rgba -out c.rgba -K 0123456789abcdeffedcba9876543210 -iv ffffffffffffffffffffffffffffffff
```

输入的K和iv应是128bit长的，也就是16字节长的，如果过长会截断，过短会补0。
