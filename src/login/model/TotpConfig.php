<?php
declare(strict_types=1);

namespace wise\login\model;

use think\Model;
use think\model\concern\SoftDelete;

/**
 * TOTP 配置模型（多态关联）
 *
 * 表：auth_totp_configs
 *
 * 通过 user_type + user_id 联合键关联用户，支持 admin / member 等多种用户类型，
 * 无需修改用户原表结构。
 *
 * ── 软删除 ──
 * 后台「删除 TOTP 配置」为软删除（delete_time），可由 delete() / restore() 撤销；
 * delete_time 为可空 datetime，NULL = 未删除（列见迁移
 * 20251020000006_add_delete_time_to_totp_config_table）。
 */
class TotpConfig extends Model
{
    use SoftDelete;

    protected $name = 'auth_totp_configs';

    protected $autoWriteTimestamp = true;
    protected $createTime = 'create_time';
    protected $updateTime = 'update_time';

    /** @var string 软删除字段 */
    protected $deleteTime = 'delete_time';

    /**
     * 「未删除」标记值：NULL
     *
     * 与框架默认一致（think\Model 的 $defaultSoftDelete 未赋默认值即为 null），
     * 此处显式声明只为与 app\common\model\BaseModel、wise-member Member 保持同一口径。
     * 切勿写成 0：列是可空 datetime，框架会把过滤条件拼成 `delete_time = 0`，
     * 而真实行是 NULL，导致正常记录全部查不到（详见 wise-member Member 的踩坑注释）。
     *
     * @var int|string|null
     */
    protected $defaultSoftDelete = null;

    /** @var string[] 隐藏字段（delete_time 与 TOTP 机密一律不对外输出） */
    protected $hidden = ['delete_time', 'totp_secret', 'totp_backup_codes', 'totp_recovery_codes'];

    /** @var string[] 追加的虚拟字段（后台列表展示掩码值，不含真实密钥） */
    protected $append = ['secret_masked'];

    /**
     * 掩码后的密钥（仅供后台列表展示前 8 位，避免明文密钥经接口外泄）
     */
    protected function getSecretMaskedAttr($value, $data): string
    {
        $secret = (string) ($data['totp_secret'] ?? '');
        return $secret === '' ? '' : substr($secret, 0, 8) . '••••';
    }


    /**
     * 按用户类型筛选
     */
    public function scopeOfUserType($query, ?string $userType)
    {
        if ($userType !== null && $userType !== '') {
            $query->where('user_type', $userType);
        }
    }

    /**
     * 仅已启用 TOTP 的记录
     */
    public function scopeEnabled($query)
    {
        $query->where('totp_enabled', 1);
    }

    /**
     * 仅未启用 TOTP 的记录
     */
    public function scopeDisabled($query)
    {
        $query->where('totp_enabled', 0);
    }

    /**
     * 按用户 ID 搜索
     */
    public function scopeSearch($query, ?string $keyword)
    {
        if ($keyword !== null && $keyword !== '') {
            $escaped = addcslashes($keyword, '%_');
            $query->where('user_id', 'like', "%{$escaped}%");
        }
    }


    /**
     * 分页列表
     *
     * @param int   $page    页码
     * @param int   $limit   每页条数
     * @param array $filters 筛选条件：user_type, enabled (1/0/null=全部), keyword
     * @return array ['total' => int, 'list' => array]
     */
    public static function getList(int $page = 1, int $limit = 15, array $filters = []): array
    {
        $query = static::order('update_time', 'desc');

        if (!empty($filters['user_type'])) {
            $query->ofUserType($filters['user_type']);
        }
        if (isset($filters['enabled']) && $filters['enabled'] !== '' && $filters['enabled'] !== null) {
            $query->where('totp_enabled', (int) $filters['enabled']);
        }
        if (!empty($filters['keyword'])) {
            $query->search($filters['keyword']);
        }

        $total = $query->count();
        $list  = $query->page($page, $limit)->select()->toArray();

        return [
            'total' => $total,
            'list'  => $list,
        ];
    }

    /**
     * 强制关闭指定用户的 TOTP
     */
    public function forceDisable(): self
    {
        $this->totp_enabled       = 0;
        $this->totp_secret        = null;
        $this->totp_backup_codes  = null;
        $this->totp_recovery_codes = null;
        $this->save();
        return $this;
    }

    /**
     * 重置密钥（用户下次登录需重新绑定）
     */
    public function resetSecret(): self
    {
        $this->totp_secret        = null;
        $this->totp_backup_codes  = null;
        $this->totp_recovery_codes = null;
        $this->save();
        return $this;
    }

    /**
     * 检查指定用户是否已启用 TOTP
     */
    public static function isEnabled(string $userType, int $userId): bool
    {
        $config = static::where('user_type', $userType)
            ->where('user_id', $userId)
            ->find();
        return $config && (int) $config->totp_enabled === 1;
    }
}
