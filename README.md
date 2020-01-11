# 使用说明
## 运行测试脚本方式：
### 运行ompopenapi相关的测试用例
* 进入项目的根目录(testcases\ompopenapi\)，执行以下命令：
```
    hrun --dot-env-path=env\omp-test-jcloud00.env testcases
```
* 测试结果默认保存在当前目录的report目录下

### 运行ompopenapi中的测试用例脚本describeApiByName-API-check.yaml
* 进入项目的根目录，执行以下命令：
```
    hrun --dot-env-path=env\omp-test-jcloud00.env testcases\describeApiByName-API-check.yaml
```
* 测试结果默认保存在当前目录的report目录下
