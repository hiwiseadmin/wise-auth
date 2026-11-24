<?php
declare(strict_types=1);

use think\migration\Migrator;
use think\migration\db\Column;

/**
 * 用户设备表
 */
class CreateUserDevicesTable extends Migrator
{
    protected function getTable(): string
    {
        return 'auth_devices';
    }

    public function up(): void
    {
        $table = $this->table($this->getTable(), [
            'engine' => 'InnoDB',
            'comment' => '用户设备表',
            'collation' => 'utf8mb4_unicode_ci',
        ]);

        $table->addColumn(Column::bigInteger('user_id')->setDefault(0)->setNull(false)->setComment('用户ID'))
              ->addColumn(Column::string('device_fingerprint', 128)->setNull(false)->setComment('设备指纹（sha256）'))
              ->addColumn(Column::string('device_name', 50)->setNull(true)->setComment('用户/系统命名'))
              ->addColumn(Column::string('ip', 45)->setNull(true)->setComment('最近一次使用 IP'))
              ->addColumn(Column::string('user_agent', 500)->setNull(true))
              ->addColumn(Column::bigInteger('last_used_at')->setDefault(0)->setNull(false)->setComment('最近使用时间'))
              ->addColumn(Column::integer('is_trusted')->setDefault(0)->setNull(false)->setComment('0/1 是否信任'))
              ->addColumn(Column::bigInteger('trusted_at')->setDefault(0)->setNull(false)->setComment('信任时间'))
              ->addColumn(Column::bigInteger('trust_expire_at')->setDefault(0)->setNull(false)->setComment('信任到期时间'))
              ->addColumn(Column::dateTime('create_time')->setNull(false)->setComment('创建时间'))
              ->addColumn(Column::dateTime('update_time')->setNull(false)->setComment('更新时间'))
              ->addIndex(['user_id'])
              ->addIndex(['user_id', 'device_fingerprint'], ['unique' => true])
              ->addIndex(['is_trusted'])
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
