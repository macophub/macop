# macop

## 安装
```bash
go install github.com/macophub/macop@latest
```

## 创建一个MCP， 推送到docker hub
1 创建文件 `mcpfile.yaml` 如下所示
```yaml
version: '1' # 打包格式版本
metadata:
  image: xxx/xxx:v1.8 # 镜像名称
spec:
  entrypoint: yyy # 入口文件
  builds: # 构建清单
    - architecture: amd64 # CPU架构
      os: linux # 操作系统
      binFilepath: yourfile # 二进制文件路径
    - architecture: arm64 # CPU架构
      os: linux # 操作系统
      binFilepath: yourfile # 二进制文件路径
    - architecture: arm64 # CPU架构
      os: darwin # 操作系统
      binFilepath: yourfile # 二进制文件路径
```
2 执行创建指令
```bash
macop create --file mcpfile.yaml
```
3 执行推送指令
```bash
macop push --image=xxx/xxx:v1.8 --username={youername} --password={yourpassword}
```

## 拉取一个MCP
```bash
macop push --pull=xxx/xxx:v1.8 --username={youername} --password={yourpassword}
```
拉取过程会根据你的操作系统，拉取对应的二进制MCP，如果不满足条件，就不会拉取到二进制
然后下载完二进制后，会展示二进制名，然后根据地址就可以运行
```bash
 Your exec file is /Users/askuy/.macop/mcps/run/registry-1.docker.io/xxx/xxx/v1.8/yyy
```
