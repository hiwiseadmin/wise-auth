<?php
/**
 * Role 的测试替身
 *
 * `Role::getAncestorIds()` 内部用 `static::find()` 查库，单元测试环境没有数据库连接，
 * 直接调用会报 "Call to a member function connect() on null"。
 *
 * 这里只覆盖 `find()`，把「查库」换成内存查表，从而在**不改生产代码**的前提下测到
 * path 解析 / 父链回溯 / 防环 三块逻辑。
 */
namespace wise\auth\tests\fixtures;

use wise\auth\model\Role;

class AncestorTestRole extends Role
{
    /**
     * 内存表：id => Role 实例
     *
     * @var array<int, static>
     */
    public static array $rows = [];

    public static function reset(): void
    {
        self::$rows = [];
    }

    public static function find($data)
    {
        return self::$rows[(int) $data] ?? null;
    }
}
