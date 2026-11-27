<?php
namespace App\Services;

use InvalidArgumentException;

class CargoService {
    public function averageNetWeight(
        float $totalKg,
        float $tareKg,
        int $containerCount
    ): float {
        if ($containerCount <= 0) {
            throw new InvalidArgumentException("containerCount must be positive");
        }
        if ($totalKg < 0) {
            throw new InvalidArgumentException("totalKg cannot be negative");
        }
        $netKg = max(0.0, $totalKg - $tareKg);
        return round($netKg / $containerCount, 3);
    }
}
