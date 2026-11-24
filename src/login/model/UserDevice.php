<?php
declare(strict_types=1);

namespace wise\login\model;

use think\Model;

/**
 * 用户设备模型
 *
 * 表：auth_devices
 */
class UserDevice extends Model
{
    protected $name = 'auth_devices';

    protected $autoWriteTimestamp = true;
    protected $createTime = 'create_time';
    protected $updateTime = 'update_time';

    /**
     * 按关键词搜索（user_id / device_name / ip）
     */
    public function scopeSearch($query, ?string $keyword)
    {
        if ($keyword !== null && $keyword !== '') {
            $escaped = addcslashes($keyword, '%_');
            $query->where(function ($q) use ($escaped) {
                $q->where('device_name', 'like', "%{$escaped}%")
                  ->whereOr('ip', 'like', "%{$escaped}%")
                  ->whereOr('user_id', 'like', "%{$escaped}%");
            });
        }
    }

    /**
     * 仅信任设备
     */
    public function scopeTrusted($query)
    {
        $query->where('is_trusted', 1);
    }

    /**
     * 仅非信任设备
     */
    public function scopeUntrusted($query)
    {
        $query->where('is_trusted', 0);
    }

    /**
     * 按日期范围筛选（last_used_at 字段，Unix 时间戳）
     */
    public function scopeDateBetween($query, ?string $start, ?string $end)
    {
        if ($start) {
            $ts = strtotime($start);
            if ($ts !== false) {
                $query->where('last_used_at', '>=', $ts);
            }
        }
        if ($end) {
            $ts = strtotime($end . ' 23:59:59');
            if ($ts !== false) {
                $query->where('last_used_at', '<=', $ts);
            }
        }
    }

    /**
     * 分页列表
     *
     * @param int   $page    页码
     * @param int   $limit   每页条数
     * @param array $filters 筛选条件：keyword, is_trusted (0/1/null=全部), date_start, date_end
     * @return array ['total' => int, 'list' => array]
     */
    public static function getList(int $page = 1, int $limit = 15, array $filters = []): array
    {
        $query = static::order('last_used_at', 'desc');

        if (isset($filters['keyword']) && $filters['keyword'] !== '') {
            $query->search($filters['keyword']);
        }

        if (isset($filters['is_trusted']) && $filters['is_trusted'] !== '' && $filters['is_trusted'] !== null) {
            if ((int) $filters['is_trusted'] === 1) {
                $query->trusted();
            } else {
                $query->untrusted();
            }
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
     * 按用户统计设备数
     */
    public static function countByUser(int $userId): int
    {
        return static::where('user_id', $userId)->count();
    }

    /**
     * 信任设备
     */
    public function trust(int $days = 30): self
    {
        $this->is_trusted      = 1;
        $this->trusted_at      = time();
        $this->trust_expire_at = time() + $days * 86400;
        $this->save();
        return $this;
    }

    /**
     * 取消信任
     */
    public function untrust(): self
    {
        $this->is_trusted      = 0;
        $this->trusted_at      = 0;
        $this->trust_expire_at = 0;
        $this->save();
        return $this;
    }
}
