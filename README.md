# ejsonkms

`ejsonkms` combines the [ejson library](https://github.com/Shopify/ejson) with [AWS Key Management
Service](https://aws.amazon.com/kms/) to simplify deployments on AWS. The EJSON private key is encrypted with
KMS and stored inside the EJSON file as `_private_key_enc`. Access to decrypt secrets can be controlled with IAM
permissions on the KMS key.

## Install

Precompiled binaries can be downloaded from [releases](https://github.com/envato/ejsonkms/releases).

### Go

```
go install github.com/envato/ejsonkms/cmd/ejsonkms@latest

# Move binary to somewhere on $PATH. E.g.,
sudo cp "${GOBIN:-$HOME/go/bin}/ejsonkms" /usr/local/bin/

ejsonkms
```

This will install the binary to `$GOBIN/ejsonkms`.

## Usage

Generating an EJSON file:

```
$ ejsonkms keygen --aws-region us-east-1 --kms-key-id bc436485-5092-42b8-92a3-0aa8b93536dc -o secrets.ejson
Private Key: ae5969d1fb70faab76198ee554bf91d2fffc44d027ea3d804a7c7f92876d518b
$ cat secrets.ejson
{
  "_public_key": "6b8280f86aff5f48773f63d60e655e2f3dd0dd7c14f5fecb5df22936e5a3be52",
  "_private_key_enc": "S2Fybjphd3M6a21zOnVzLWVhc3QtMToxMTExMjIyMjMzMzM6a2V5L2JjNDM2NDg1LTUwOTItNDJiOC05MmEzLTBhYThiOTM1MzZkYwAAAAAycRX5OBx6xGuYOPAmDJ1FombB1lFybMP42s7PGmoa24bAesPMMZtI9V0w0p0lEgLeeSvYdsPuoPROa4bwnQxJB28eC6fHgfWgY7jgDWY9uP/tgzuWL3zuIaq+9Q=="
}
```

> [!NOTE]
> If either of the `AWS_REGION` or `AWS_DEFAULT_REGION` environment variables is set, it will be used implicitly for `--aws-region` when the flag is not provided.

Encrypting:

```
$ ejsonkms encrypt secrets.ejson
```

Decrypting:

```
$ ejsonkms decrypt secrets.ejson
{
  "_public_key": "6b8280f86aff5f48773f63d60e655e2f3dd0dd7c14f5fecb5df22936e5a3be52",
  "_private_key_enc": "S2Fybjphd3M6a21zOnVzLWVhc3QtMToxMTExMjIyMjMzMzM6a2V5L2JjNDM2NDg1LTUwOTItNDJiOC05MmEzLTBhYThiOTM1MzZkYwAAAAAycRX5OBx6xGuYOPAmDJ1FombB1lFybMP42s7PGmoa24bAesPMMZtI9V0w0p0lEgLeeSvYdsPuoPROa4bwnQxJB28eC6fHgfWgY7jgDWY9uP/tgzuWL3zuIaq+9Q==",
  "environment": {
    "my_secret": "secret123"
  }
}
```

Exporting shell variables (from [ejson2env](https://github.com/Shopify/ejson2env)):

```
$ exports=$(ejsonkms env secrets.ejson)
$ echo $exports
export my_secret=secret123
$ eval $exports
$ echo my_secret
secret123
```

Note that only secrets under the "environment" key will be exported using the `env` command.

## pre-commit hook

A [pre-commit](https://pre-commit.com/) hook is also supported to automatically run `ejsonkms encrypt` on all `.ejson` files in a repository.

To use, add the following to a `.pre-commit-config.yaml` file in your repository:

```yaml
repos:
  - repo: https://github.com/envato/ejsonkms
    hooks:
      - id: run-ejsonkms-encrypt
```
