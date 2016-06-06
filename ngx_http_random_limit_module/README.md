# ngx_http_random_limit_req_module #

配合日志分析系统，动态随机block request。
对外提供查询、删除、添加规则接口。
* 目前之时个测试版本，我们线上使用的是改版的。


### 例如：

```

.......

sae_limit_cache_zone_size 10M;
sae_limit_continue        300s;

location /rule {
    sae_random_limit;
    allow 127.0.0.1;
    deny all;
}

location / {
    
    ......

    if ($sae_limit_act = "deny") {
        return 444;
    }

    ......

}

......

```


### 配置

规则共享内存大小：

```

Syntax: sae_limit_cache_zone_size size;
Context: server

```

规则默认有效时长：单位：秒

```

Syntax: sae_limit_continue ns;
Default: sae_limit_continue 300s;
Context: server

```

该类型的文件不受规则的限制：

```

Syntax: sae_limit_ignore_types [.css] [.js];
Default: sae_limit_ignore_types null;
Context: server

```

规则设置api:

```

Syntax: sae_random_limit;
Context: location

```

### 变量

```

$sae_limit_act
#取值：
allow, deny

deny: 表示请求触发规则。

```


### API

```

#1. 设置规则：
http://xxx.com/rule/set?domain=xxx.xxx&ratio=n[&expire=100]
说明：
成功返回ok
失败返回err
domain:limit域名
ratio:limit比例，取值[1-9]。每10个请求拒绝n个
expire:规则有效时长，如果不设置expire，取默认的有效时长，参考‘sae_limit_continue’。


#2. 失效规则：
http://xxx.com/rule/set?domain=xxx.xxx&expire=0
说明：
如果你确定该规则还要设置，只是暂时放开，建议调用该接口。


#3. 删除规则：
http://xxx.com/rule/del?domain=xxx.xxx


#4. 查看规则：
http://xxx.com/rule/get[?domain=xxx.xxx[&expire=1]]
说明：
如果不指定参数，dump所有生效的规则。
如果指定domain，dump该domain的规则,如果指定expire＝0，dump指定domain且生效的规则。
如果指定expire＝0，dump所有的规则。
没有生效的规则，返回 null。


```