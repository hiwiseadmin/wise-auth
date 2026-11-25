<?php
declare(strict_types=1);

namespace wise\login\model;

use think\Model;

/**
 * IP 黑白名单模型＼�
 *
 * 提供数据库方式的 IP 列表管理。
 * 字段：cidr（网段）、type（whitelist/blacklist）、status（启用/禁用）、remark（备注）
 */
class IpList extends Model
{
    protected $name = 'auth_ip_lists';

    protected $autoWriteTimestamp = true;
    protected $createTime = 'create_time';
    protected $updateTime = 'update_time';


    /**
     * 按类型筛选
     */
    public function scopeOfType($query, ?string $type)
    {
        if ($type !== null && $type !== '') {
            $query->where('type', $type);
        }
    }

    /**
     * 按状态筛选
     */
    public function scopeOfStatus($query, ?int $status)
    {
        if ($status !== null && $status !== '') {
            $query->where('status', (int) $status);
        }
    }

    /**
     * 仅启用
     */
    public function scopeActive($query)
    {
        $query->where('status', 1);
    }

    /**
     * 按 CIDR 关键词搜索
     */
    public function scopeSearch($query, ?string $keyword)
    {
        if ($keyword !== null && $keyword !== '') {
            $escaped = addcslashes($keyword, '%_');
            $query->where(function ($q) use ($escaped) {
                $q->where('cidr', 'like', "%{$escaped}%")
                  ->whereOr('remark', 'like', "%{$escaped}%");
            });
        }
    }


    /**
     * 分页列表
     *
     * @param int   $page    页码
     * @param int   $limit   每页条数
     * @param array $filters 筛选条件：type (whitelist/blacklist), status (0/1), keyword
     * @return array ['total' => int, 'list' => array]
     */
    public static function getList(int $page = 1, int $limit = 15, array $filters = []): array
    {
        $query = static::order('id', 'desc');

        if (!empty($filters['type'])) {
            $query->ofType($filters['type']);
        }
        if (isset($filters['status']) && $filters['status'] !== '' && $filters['status'] !== null) {
            $query->ofStatus((int) $filters['status']);
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
     * 切换启用/禁用状态
     */
    public function toggle(): self
    {
        $this->status = $this->status ? 0 : 1;
        $this->save();
        return $this;
    }


    /**
     * 获取所有启用的白名单 CIDR
     *
     * @return string[]
     */
    public static function getActiveWhitelist(): array
    {
        return static::where('type', 'whitelist')
            ->where('status', 1)
            ->column('cidr');
    }

    /**
     * 获取所有启用的黑名单 CIDR
     *
     * @return string[]
     */
    public static function getActiveBlacklist(): array
    {
        return static::where('type', 'blacklist')
            ->where('status', 1)
            ->column('cidr');
    }
}
