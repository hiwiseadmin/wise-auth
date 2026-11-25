<?php
declare(strict_types=1);

namespace wise\login\detector;

/**
 * 异常检测结果值对象＼�
 */
class AnomalyResult
{
    /** 严重程度 */
    public const SEVERITY_LOW    = 'low';
    public const SEVERITY_MEDIUM = 'medium';
    public const SEVERITY_HIGH   = 'high';

    /**
     * @param string $type     异常类型（geo_anomaly / new_device_ip / time_anomaly / frequency_anomaly）
     * @param string $severity 严重程度（low / medium / high）
     * @param string $message  描述信息
     * @param array  $data     附加数据
     */
    public function __construct(
        public readonly string $type,
        public readonly string $severity,
        public readonly string $message,
        public readonly array $data = [],
    ) {
    }

    public function toArray(): array
    {
        return [
            'type'     => $this->type,
            'severity' => $this->severity,
            'message'  => $this->message,
            'data'     => $this->data,
        ];
    }
}
