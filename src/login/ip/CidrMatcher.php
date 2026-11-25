<?php
declare(strict_types=1);

namespace wise\login\ip;

use think\Request;

/**
 * IP CIDR 匹配器
 *
 * 支持 IPv4 / IPv6 / CIDR（192.168.0.0/24, 2001:db8::/32）
 * 纯 PHP 实现，不依赖任何扩展
 */
class CidrMatcher
{
    /**
     * 判断 IP 是否在 CIDR 列表中匹配
     *
     * @param string       $ip     IPv4 或 IPv6 地址
     * @param string[]     $cidrs  CIDR 或单 IP 列表
     * @return bool
     */
    public static function match(string $ip, array $cidrs): bool
    {
        foreach ($cidrs as $cidr) {
            if (self::matchSingle($ip, $cidr)) {
                return true;
            }
        }
        return false;
    }

    /**
     * 判断 IP 是否匹配单个 CIDR（或单 IP）
     */
    public static function matchSingle(string $ip, string $cidr): bool
    {
        $cidr = trim($cidr);
        if ($cidr === '') {
            return false;
        }

        if (!str_contains($cidr, '/')) {
            $ipPacked   = inet_pton($ip);
            $cidrPacked = inet_pton($cidr);
            if ($ipPacked === false || $cidrPacked === false) {
                return false;
            }
            return $ipPacked === $cidrPacked;
        }

        [$subnet, $bits] = explode('/', $cidr, 2);
        $bits = (int) $bits;

        $isV6 = str_contains($ip, ':') || str_contains($cidr, ':');
        $maxBits = $isV6 ? 128 : 32;

        if ($bits < 0 || $bits > $maxBits) {
            return false;
        }

        $ipBin     = self::ipToBin($ip, $isV6);
        $subnetBin = self::ipToBin($subnet, $isV6);

        if ($ipBin === null || $subnetBin === null) {
            return false;
        }

        if ($bits === 0) {
            return true;
        }

        return substr($ipBin, 0, $bits) === substr($subnetBin, 0, $bits);
    }

    /**
     * 将 IP 转换为定长二进制字符串
     */
    private static function ipToBin(string $ip, bool $isV6): ?string
    {
        $packed = inet_pton($ip);
        if ($packed === false) {
            return null;
        }

        if ($isV6) {
            if (strlen($packed) !== 16) {
                return null;
            }
        } else {
            if (strlen($packed) !== 4) {
                return null;
            }
        }

        $bin = '';
        foreach (str_split($packed) as $byte) {
            $bin .= str_pad(decbin(ord($byte)), 8, '0', STR_PAD_LEFT);
        }
        return $bin;
    }

    /**
     * 从请求中获取客户端真实 IP
     *
     * 优先级：X-Forwarded-For（首个有效 IP）> X-Real-IP > REMOTE_ADDR
     *
     * SEC-5 修复：新增 $trustedProxies 参数，在信任 X-Forwarded-For 前
     * 验证 REMOTE_ADDR 是否在可信代理 CIDR 列表中，防止伪造头攻击
     *
     * @param array    $server           $_SERVER 数组（便于测试）
     * @param bool     $trustProxyHeader 是否信任 X-Forwarded-For
     * @param string[] $trustedProxies   可信代理 IP 的 CIDR 列表；为空时不信任代理头（fail-closed）
     * @return string 客户端 IP 地址
     */
    public static function getClientIp(array $server, bool $trustProxyHeader = true, array $trustedProxies = []): string
    {
        $remote = $server['REMOTE_ADDR'] ?? '0.0.0.0';

        if (!$trustProxyHeader) {
            return $remote;
        }

        if (empty($trustedProxies) || !self::match($remote, $trustedProxies)) {
            return $remote;
        }

        $xff = $server['HTTP_X_FORWARDED_FOR'] ?? $server['HTTP_X_REAL_IP'] ?? null;
        if (is_string($xff) && $xff !== '') {
            $parts = array_map('trim', explode(',', $xff));
            $trustingProxies = !empty($trustedProxies);
            foreach ($parts as $candidate) {
                if ($candidate === '' || strtolower($candidate) === 'unknown') {
                    continue;
                }
                if (!filter_var($candidate, FILTER_VALIDATE_IP)) {
                    continue;
                }
                if ($trustingProxies && self::match($candidate, $trustedProxies)) {
                    continue;
                }
                return $candidate;
            }
        }

        return $remote;
    }

    /**
     * 从请求对象解析客户端真实 IP（统一读取 ip_list 的信任代理配置）
     *
     * 守卫侧（LoginGuardMiddleware/IpGuardMiddleware）与结果侧
     * （FailureRecordAction/SuccessRecordAction/AnomalyDetectAction）
     * 必须经由同一入口解析，否则反代环境下写入的失败计数 key
     * 与 isLocked() 检查的 key 不一致，锁定形同虚设。
     *
     * @param Request $request 当前请求
     * @return string 客户端 IP
     */
    public static function fromRequest(Request $request): string
    {
        return self::getClientIp(
            $request->server(),
            (bool) config('wise-auth.login.ip_list.trust_proxy_header', true),
            (array) config('wise-auth.login.ip_list.trusted_proxies', [])
        );
    }
}
