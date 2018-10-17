<?php
/**
 * Created by PhpStorm.
 * User: Felipe
 * Date: 17/10/2018
 * Time: 10:13
 */

namespace Laravel\Passport\Traits;

use Illuminate\Support\Str;

trait UuidTrait
{
    protected static function boot()
    {
        parent::boot();

        static::creating(function ($model) {
            $model->{$model->getKeyName()} = (string) Str::uuid();
        });
    }
}