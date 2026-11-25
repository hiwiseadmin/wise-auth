<?php
declare(strict_types=1);

namespace wise\login\model;

use think\Model;

/**
 * 登录失败记录模型
 */
class FailedAttempt extends Model
{
    protected $name = 'auth_login_attempts';

    protected $autoWriteTimestamp = true;
    protected $createTime = 'create_time';
    protected $updateTime = 'update_time';

    /**
     * 仅已过期的记录（expire_at < 当前时间）
     */
    public function scopeExpired($query)
    {
        $query->where('expire_at', '<', time())->where('expire_at', '>', 0);
    }

    /**
     * 仅未过期的记录（仍在锁定期内）
     */
    public function scopeActive($query)
    {
        $query->where('expire_at', '>=', time());
    }

    /**
     * 按关键词搜索（cache_key）
     */
    public function scopeSearch($query, ?string $keyword)
    {
        if ($keyword !== null && $keyword !== '') {
            $escaped = addcslashes($keyword, '%_');
            $query->where('cache_key', 'like', "%{$escaped}%");
        }
    }

    /**
     * 分页列表
     *
     * @param int   $page    页码
     * @param int   $limit   每页条数
     * @param array $filters 筛选条件：keyword, show_expired (true/false)
     * @return array ['total' => int, 'list' => array]
     */
    public static function getList(int $page = 1, int $limit = 15, array $filters = []): array
    {
        $query = static::order('update_time', 'desc');

        if (!empty($filters['keyword'])) {
            $query->search($filters['keyword']);
        }

        $showExpired = !empty($filters['show_expired']);
        if (!$showExpired) {
            $query->active();
        }

        $countQuery = clone $query;
        $total = $countQuery->count();

        $listQuery = clone $query;
        $list = $listQuery->page($page, $limit)->select()->toArray();

        return [
            'total' => $total,
            'list'  => $list,
        ];
    }

    /**
     * 清理已过期的失败记录
     *
     * @return int 删除条数
     */
    public static function clearExpired(): int
    {
        return (int) static::query()
            ->where('expire_at', '<', time())
            ->where('expire_at', '>', 0)
            ->delete();
    }

    /**
     * 按 cache_key 查找记录
     */
    public static function findByCacheKey(string $cacheKey): ?static
    {
        return static::where('cache_key', $cacheKey)->find();
    }
}
