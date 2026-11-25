<?php
declare(strict_types=1);

namespace wise\login\contract;

/**
 * 用户模型需实现的 TOTP 契约
 *
 * 业务层 User 模型需 implements 此接口并实现以下方法。
 *
 * 推荐使用 HasTotp Trait（wise\login\traits\HasTotp）快速实现，
 * 数据自动存入包内自建表 auth_totp_configs（多态关联），
 * 不修改用户原表结构。
 *
 * 包内默认使用 sha1 / 6 位 / 30s
 */
interface TotpUserInterface
{
    /**
     * 获取用户唯一标识（用于 TOTP label）
     */
    public function getTotpLabel(): string;

    /**
     * 获取多态用户类型标识（用于关联 TotpConfig 表）
     *
     * 例如：'admin' / 'member' / 'user'
     */
    public function getTotpUserType(): string;

    /**
     * 获取 TOTP 密钥（Base32 编码），未启用时返回 null 或 ''
     */
    public function getTotpSecret(): ?string;

    /**
     * 保存 TOTP 密钥
     */
    public function setTotpSecret(?string $secret): void;

    /**
     * 获取备份码集合（hash 后存储）
     *
     * @return array<string, bool> [code_hash => true]
     */
    public function getBackupCodes(): array;

    /**
     * 保存备份码集合
     *
     * @param array<string, bool> $codes
     */
    public function setBackupCodes(array $codes): void;

    /**
     * 获取恢复码集合＼�
     *
     * @return array<string, bool> [code_hash => true]
     */
    public function getRecoveryCodes(): array;

    /**
     * 保存恢复码集合＼�
     *
     * @param array<string, bool> $codes
     */
    public function setRecoveryCodes(array $codes): void;

    /**
     * 是否已启用 TOTP
     */
    public function isTotpEnabled(): bool;

    /**
     * 设置 TOTP 启用状态
     */
    public function setTotpEnabled(bool $enabled): void;
}
