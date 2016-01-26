/*
 * A white-list based PAC
 * Special thanks to @Paveo,@janlay
 */
 
/*
  Supports * in the pattern. * can be anywhere, not restricted to the string head.
*/
function shExpMatch3(url, pattern){
  var reg = /\*/g;
  var tmpStr = pattern.replace(reg,'([^\\s]+)?');
  reg = /\./g;
  tmpStr = tmpStr.replace(reg,'\\.');
  tmpPattern = new RegExp(tmpStr);

  return tmpPattern.test(url);
}

function isIP4Addr(url){
  ipv4Reg = /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
  return ipv4Reg.test(url);
}

function FindProxyForURL(url, host) {
    // REPLACE PROXY WITH YOUR OWN'S
    var PROXY = "PROXY 192.168.1.200:8787";
    var BLACKHOLE = "127.0.0.2";
    var DEFAULT = "DIRECT";

    var parts = host.split('.'),
        firstPart = parts[0],
        // always use proxy, even if domains are matched
        overrideDomains = ['*google*', '*twitter*', '*twimg*', '*amazonaws*', '*facebook*'],
        // domain/host starts with
        prefixes = ['cn', 'china'],
        // privacy trackers
        blockedHosts = ['mmstat.com', 'googlesyndication.com', '127.net'],
        // domains end with
        domains = ['cn$', 'taobao', 'tmall.com', 'alipay', 'qq.com', 'tencent', 'netease.com', '163', '51', 'baidu',
        'img.com', '189.cn', '39.net', 'apple.com.cn', 'baixing.com', 'go2map.com', 'blueidea.com', 'caing.com',
        'ccb.com', 'comsenz.com', 'csdn.net', 'ctrip.com', 'dangdang', 'dianping', 'dingtalk', 'discuz.net',
        'donews.com', 'douban', 'dream4ever.org', 'eastmoney', 'et8', 'ecitic', 'fastspring', 'fengniao', 'xitek',
        'hupu', 'futu5', 'ganji', 'gfan', 'gfw.io', 'gougou', 'weiqitv', 'hi-pda', 'huaban', 'huanqiu', 'hudong',
        'iciba', 'ihg.com', 'img-space', 'infzm', 'ip138', 'jandan', 'jd.com', 'jiepang.com', 'ku6.com', 'lampdrive',
        'live.net', 'etao.com', 'mapabc.com', 'mapbar.com', 'meituan.com', 'mi.com', 'miwifi.com', 'microsoft',
        'onenote.com', 'macpaw.com', 'mozilla.org', 'mop.com', 'mtime.com', 'mydrivers.com',  'nuomi.com', 'onlinedown',
         'paipai.com', 'qiyi.com', 'qunar.com', 'renren.com', 'sdo.com', 'sf-express.com', 'iask.com', 'sogou', 'sohu',
         'sina', 'soso.com', 'soufun', 'stackoverflow.com', 'superuser.com', 'tenpay.com', 'tgbus.com',  'tudou',
         'uusee.com', 'verycd.com', 'weibo.com', 'weiphone.com', 'feng.com', 'xiami', '*xinhuanet', 'xinnet', 'xunlei', 'yesky',
         'yihaodian', 'ynet.com', 'youdao.com', 'youku', 'letv', 'iqiyi', 'yupoo.com', 'zaobao', 'zhaopin', 'zhihu.com',
         'my.cl.ly', 'synacast.com', 'xiachufang', 'wandoujia', 'chdbits', 'hdwing', 'zhi*hu', 'join.me', 'imgur.com',
         'amazon.cn', 'z.cn', 'smzdm', 'ycombinator', 'v2ex.com', 'verisign', 'laiwang', 'hiwifi', 'tanx'];

    // ignore local host name. eg: http://localhost
    if (isPlainHostName(host)) return DEFAULT;

    // force proxy by url. eg: http://foo.com/?bar=1&fuckgfw
    if (url.indexOf('fuckgfw') > 0) return PROXY;

    // bypass plain IP
    if(isIP4Addr(host))
        return DEFAULT;

    var i, len;
    // block privacy trackers
    /*
    for (i = 0, len = blockedHosts.length; i < len; i++)
        if (shExpMatch3(host,blockedHosts[i])) return BLACKHOLE;
    */
    // force proxy by domain. eg: http://cn.nytimes.com
    for (i = 0, len = overrideDomains.length; i < len; i++)
        if (shExpMatch3(host,overrideDomains[i])) return PROXY;

    // domain/ip prefix. eg: http://60.1.2.3
    for (i = 0, len = prefixes.length; i < len; i++)
        if (prefixes[i] === firstPart) return DEFAULT;

    // match main domain. eg: http://www.verycd.com, http://ip138.com/
    for (i = 0, len = domains.length; i < len; i++)
        if (shExpMatch3(host,domains[i])) return DEFAULT;

    // for all other host, default to proxy.
    return PROXY;
}
