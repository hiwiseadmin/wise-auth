<?php
declare(strict_types=1);

namespace wise\login\traits;

use wise\login\model\TotpConfig;

/**
 * TOTP 用户 Trait — 简化 TotpUserInterface 的实现
 *
 * 数据存储于包内自建表 auth_totp_configs（多态关联），
 * 不修改用户原表结构。通过 user_type + user_id 联合键支持
 * admin / member 等多种用户类型。
 *
 * 用户模型只需：
 * 1. use HasTotp;
 * 2. 实现 getTotpLabel() 方法
 * 3. （可选）覆盖 $totpUserType 属性指定用户类型，默认 'admin'
 *
 * @example
 *   class Admin extends Model implements TotpUserInterface
 *   {
 *       use HasTotp;
 *
 *       public function getTotpLabel(): string
 *       {
 *           return $this->username;
 *       }
 *   }
 *
 * @see \wise\login\contract\TotpUserInterface
 * @see \wise\login\model\TotpConfig
 */
trait HasTotp
{
    /** @var string 多态类型标识：admin / member / ... */
    protected string $totpUserType = 'admin';

    /** @var TotpConfig|null 缓存实例，避免重复查询 */
    private ?TotpConfig $totpConfigInstance = null;


    /**
     * 获取 TOTP 标签（用户唯一标识，用于生成 otpauth:// URI）
     *
     * @return string
     */
    abstract public function getTotpLabel(): string;


    /**
     * 获取用户类型标识（多态键）
     *
     * 默认返回 $this->totpUserType，模型可覆盖此方法
     *
     * @return string
     */
    public function getTotpUserType(): string
    {
        return $this->totpUserType;
    }


    /**
     * 持久化 TOTP 配置到数据库
     *
     * 在调用 setTotpSecret() / setBackupCodes() / setTotpEnabled() 之后调用。
     *
     * @return bool
     */
    public function saveTotpConfig(): bool
    {
        if ($this->totpConfigInstance === null) {
            return false;
        }

        $config = $this->totpConfigInstance;

        if (!$config->isExists()) {
            $trashed = TotpConfig::onlyTrashed()
                ->where('user_type', $this->getTotpUserType())
                ->where('user_id', $this->getKey())
                ->find();

            if ($trashed !== null) {
                $data = $config->getData();
                $trashed->setAttr('delete_time', null);

                foreach ($data as $field => $value) {
                    if (in_array($field, ['id', 'create_time', 'update_time', 'delete_time'], true)) {
                        continue;
                    }
                    $trashed->setAttr($field, $value);
                }

                $config = $this->totpConfigInstance = $trashed;
            }
        }

        return $config->save() !== false;
    }


    /**
     * 获取 TOTP 密钥（Base32 编码），未启用时返回 null
     *
     * @return string|null
     */
    public function getTotpSecret(): ?string
    {
        $value = $this->totpConfig()->getAttr('totp_secret');
        return ($value !== null && $value !== '') ? $value : null;
    }

    /**
     * 保存 TOTP 密钥（暂存，需调用 saveTotpConfig() 持久化）
     *
     * @param string|null $secret
     */
    public function setTotpSecret(?string $secret): void
    {
        $this->totpConfig()->setAttr('totp_secret', $secret);
    }


    /**
     * 获取备份码集合（hash 后存储）
     *
     * @return array<string, bool> [code_hash => true]
     */
    public function getBackupCodes(): array
    {
        $raw = $this->totpConfig()->getAttr('totp_backup_codes');
        if (empty($raw)) {
            return [];
        }
        $decoded = json_decode($raw, true);
        return is_array($decoded) ? $decoded : [];
    }

    /**
     * 保存备份码集合（暂存，需调用 saveTotpConfig() 持久化）
     *
     * @param array<string, bool> $codes
     */
    public function setBackupCodes(array $codes): void
    {
        $json = json_encode($codes, JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
        $this->totpConfig()->setAttr('totp_backup_codes', $json);
    }


    /**
     * 获取恢复码集合（hash 后存储）
     *
     * @return array<string, bool> [code_hash => true]
     */
    public function getRecoveryCodes(): array
    {
        $raw = $this->totpConfig()->getAttr('totp_recovery_codes');
        if (empty($raw)) {
            return [];
        }
        $decoded = json_decode($raw, true);
        return is_array($decoded) ? $decoded : [];
    }

    /**
     * 保存恢复码集合（暂存，需调用 saveTotpConfig() 持久化）
     *
     * @param array<string, bool> $codes
     */
    public function setRecoveryCodes(array $codes): void
    {
        $json = json_encode($codes, JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
        $this->totpConfig()->setAttr('totp_recovery_codes', $json);
    }


    /**
     * 是否已启用 TOTP
     *
     * @return bool
     */
    public function isTotpEnabled(): bool
    {
        return (bool) $this->totpConfig()->getAttr('totp_enabled');
    }

    /**
     * 设置 TOTP 启用状态（暂存，需调用 saveTotpConfig() 持久化）
     *
     * @param bool $enabled
     */
    public function setTotpEnabled(bool $enabled): void
    {
        $this->totpConfig()->setAttr('totp_enabled', $enabled ? 1 : 0);
    }


    /**
     * 获取或初始化 TotpConfig 实例（懒加载 + 缓存）
     *
     * 按 user_type + user_id 查询，不存在时自动创建新实例
     *
     * @return TotpConfig
     */
    protected function totpConfig(): TotpConfig
    {
        if ($this->totpConfigInstance !== null) {
            return $this->totpConfigInstance;
        }

        $config = TotpConfig::where('user_type', $this->getTotpUserType())
            ->where('user_id', $this->getKey())
            ->find();

        if (!$config) {
            $config = new TotpConfig();
            $config->setAttr('user_type', $this->getTotpUserType());
            $config->setAttr('user_id', $this->getKey());
        }

        return $this->totpConfigInstance = $config;
    }
}
