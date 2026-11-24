<?php
declare(strict_types=1);

namespace wise\login\model;

use think\Model;

/**
 * 安全事件日志模型
 */
class SecurityEvent extends Model
{
    protected $name = 'auth_security_events';

    protected $autoWriteTimestamp = false;
    protected $createTime = false;
    protected $updateTime = false;

    /**
     * 按事件类型筛选
     */
    public function scopeOfType($query, ?string $type)
    {
        if ($type !== null && $type !== '') {
            $query->where('event_type', $type);
        }
    }

    /**
     * 按用户名筛选
     */
    public function scopeOfUsername($query, ?string $username)
    {
        if ($username !== null && $username !== '') {
            $escaped = addcslashes($username, '%_');
            $query->where('username', 'like', "%{$escaped}%");
        }
    }

    /**
     * 按 IP 筛选
     */
    public function scopeOfIp($query, ?string $ip)
    {
        if ($ip !== null && $ip !== '') {
            $escaped = addcslashes($ip, '%_');
            $query->where('ip', 'like', "%{$escaped}%");
        }
    }

    /**
     * 按日期范围筛选（create_time datetime 字段）
     */
    public function scopeDateBetween($query, ?string $start, ?string $end)
    {
        if ($start) {
            $query->where('create_time', '>=', $start . ' 00:00:00');
        }
        if ($end) {
            $query->where('create_time', '<=', $end . ' 23:59:59');
        }
    }

    /**
     * 分页列表
     *
     * @param int   $page    页码
     * @param int   $limit   每页条数
     * @param array $filters 筛选条件：event_type, username, ip, date_start, date_end
     * @return array ['total' => int, 'list' => array]
     */
    public static function getList(int $page = 1, int $limit = 15, array $filters = []): array
    {
        $query = static::order('id', 'desc');

        if (!empty($filters['event_type'])) {
            $query->ofType($filters['event_type']);
        }
        if (!empty($filters['username'])) {
            $query->ofUsername($filters['username']);
        }
        if (!empty($filters['ip'])) {
            $query->ofIp($filters['ip']);
        }
        if (!empty($filters['date_start']) || !empty($filters['date_end'])) {
            $query->dateBetween($filters['date_start'] ?? null, $filters['date_end'] ?? null);
        }

        $total = $query->count();
        $list  = $query->page($page, $limit)->select()->toArray();

        return [
            'total' => $total,
            'list'  => $list,
        ];
    }

    /**
     * N 天内各事件类型统计
     *
     * @param int $days 最近天数
     * @return array ['event_type' => count, ...]
     */
    public static function getEventTypeStats(int $days = 7): array
    {
        $since = date('Y-m-d H:i:s', strtotime("-{$days} days"));
        return static::where('create_time', '>=', $since)
            ->group('event_type')
            ->column('COUNT(*) as cnt', 'event_type');
    }

    /**
     * 清理 N 天前的安全事件
     *
     * @param int $days 保留天数
     * @return int 删除条数
     */
    public static function clearOlderThan(int $days): int
    {
        $before = date('Y-m-d H:i:s', strtotime("-{$days} days"));
        return (int) static::where('create_time', '<', $before)->delete();
    }
}
