#!/usr/bin/env python3
"""
Оптимизированный скрипт для проверки покрытия IP-адресов агрегированными CIDR блоками
"""

import ipaddress
import sys

def check_coverage(original_file: str, aggregated_file: str):
    """Проверяет покрытие исходных IP агрегированными сетями"""
    
    # 1. Загрузка исходных IP (сразу конвертируем в int для скорости)
    print(f"Загрузка исходных IP из {original_file}...")
    target_ips_int = set()
    loaded_count = 0
    
    with open(original_file) as f:
        for row in f:
            ip_str = row.strip().split(",")[0]
            if ip_str:
                try:
                    # Сразу в int для быстрого сравнения
                    ip_int = int(ipaddress.ip_address(ip_str))
                    target_ips_int.add(ip_int)
                    loaded_count += 1
                except ValueError:
                    continue
    
    print(f"Загружено {loaded_count} строк, уникальных IP: {len(target_ips_int):,}")
    
    # 2. Загрузка сетей (конвертируем в диапазоны start-end)
    print(f"\nЗагрузка агрегированных сетей из {aggregated_file}...")
    net_ranges = []  # Список кортежей (start_int, end_int)
    
    with open(aggregated_file) as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    # strict=False важен! Позволяет принимать валидные, но "неаккуратные" CIDR
                    net = ipaddress.ip_network(line, strict=False)
                    # Преобразуем сеть в диапазон целых чисел [start, end]
                    start = int(net.network_address)
                    end = int(net.broadcast_address)
                    net_ranges.append((start, end))
                except ValueError:
                    print(f"Внимание: Некорректное правило пропущено: {line}")
                    continue
    
    # Сортировка диапазонов может немного ускорить поиск
    net_ranges.sort()
    print(f"Загружено {len(net_ranges)} CIDR блоков")
    
    # 3. Быстрая проверка покрытия через целочисленное сравнение
    print("\nПроверка покрытия (оптимизированная)...")
    missing_ints = []
    
    # Проходим по всем IP
    # Для ускорения можно было бы использовать IntervalTree, но для 2000 правил
    # простой проход по списку диапазонов с int будет достаточно быстр (секунды).
    for ip_val in target_ips_int:
        is_covered = False
        for start, end in net_ranges:
            # Математическая проверка вхождения числа в диапазон (быстрее в сотни раз)
            if start <= ip_val <= end:
                is_covered = True
                break
        
        if not is_covered:
            missing_ints.append(ip_val)
    
    # 4. Статистика
    missing_count = len(missing_ints)
    total_count = len(target_ips_int)
    covered_count = total_count - missing_count
    
    print("\n" + "="*60)
    print("РЕЗУЛЬТАТЫ ПРОВЕРКИ ПОКРЫТИЯ")
    print("="*60)
    print(f"Всего уникальных IP:       {total_count:,}")
    print(f"Покрыто правилами:         {covered_count:,} ({(covered_count/total_count)*100:.2f}%)")
    print(f"НЕ покрыто (ошибки):       {missing_count:,} ({(missing_count/total_count)*100:.2f}%)")
    print("="*60)
    
    # Детали по потерянным IP
    if missing_count > 0:
        print(f"\nПримеры непокрытых IP:")
        for ip_val in sorted(missing_ints)[:20]:
            print(f"  {ipaddress.ip_address(ip_val)}")
        if len(missing_ints) > 20:
            print(f"  ... и еще {len(missing_ints) - 20} IP")
        
        # Сохраняем потерянные IP в файл
        missing_file = "missing_ips.txt"
        with open(missing_file, 'w') as f:
            for ip_val in sorted(missing_ints):
                f.write(f"{ipaddress.ip_address(ip_val)}\n")
        print(f"\nПолный список непокрытых IP сохранен в {missing_file}")
        return False
    else:
        print("\n✅ УСПЕХ: Все 100% IP адресов покрыты правилами.")
        return True


if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("Использование: python3 check_coverage.py <исходный_файл> <агрегированный_файл>")
        print("Пример: python3 check_coverage.py 1.05_7.12_delivery_ip.csv delivery_aggregated.txt")
        sys.exit(1)
    
    original_file = sys.argv[1]
    aggregated_file = sys.argv[2]
    
    is_complete = check_coverage(original_file, aggregated_file)
    sys.exit(0 if is_complete else 1)

