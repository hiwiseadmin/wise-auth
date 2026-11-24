<?php
declare(strict_types=1);

use think\migration\Migrator;
use think\migration\db\Column;

/**
 * 登录失败计数表
 */

class CreateFailedAttemptsTable extends Migrator
{
    protected function getTable(): string
    {
        return 'auth_login_attempts';
    }

    public function up(): void
    {
        $table = $this->table($this->getTable(), [
            'engine' => 'InnoDB',
            'comment' => '登录失败计数表',
            'collation' => 'utf8mb4_unicode_ci',
        ]);

        $table->addColumn(Column::string('cache_key', 191)->setNull(false)->setComment('缓存键（含前缀）'))
              ->addColumn(Column::integer('attempts')->setDefault(0)->setNull(false)->setComment('失败次数'))
              ->addColumn(Column::bigInteger('expire_at')->setDefault(0)->setNull(false)->setComment('过期时间（Unix 时间戳）'))
              ->addColumn(Column::dateTime('create_time')->setNull(false)->setComment('创建时间'))
              ->addColumn(Column::dateTime('update_time')->setNull(false)->setComment('更新时间'))
              ->addIndex(['cache_key'], ['unique' => true])
              ->addIndex(['expire_at'])
              ->create();
    }

    public function down(): void
    {
        $tableName = $this->getTable();

        if ($this->hasTable($tableName)) {
            $this->table($tableName)->drop()->save();
        }
    }
}
