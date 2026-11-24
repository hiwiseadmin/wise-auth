<?php
declare(strict_types=1);

namespace wise\login\ip;

/**
 * IP 列表提供器接口
 *
 * 应用可自定义实现：例如从数据库 / Redis / 远程 API 动态加载黑名单
 */
interface IpListProviderInterface
{
    /**
     * 获取 IP 白名单（CIDR 数组）
     *
     * @return string[]
     */
    public function getWhitelist(): array;

    /**
     * 获取 IP 黑名单（CIDR 数组）
     *
     * @return string[]
     */
    public function getBlacklist(): array;
}
