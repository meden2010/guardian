<?php
namespace App\Services;

use App\Models\Shipment;

class CargoService {
    public function averageWeight(float $totalKg, int $containerCount): float {
        return round($totalKg / $containerCount, 2);
    }
}
