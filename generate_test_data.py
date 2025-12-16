#!/usr/bin/env python3
"""
Утилита для генерации тестовых данных IP-адресов
Создает файл с IP-адресами для тестирования агрегатора
"""

import ipaddress
import random
import argparse


def generate_sparse_ips(num_ips: int, output_file: str, density: float = 0.032):
    """
    Генерирует разреженное распределение IP-адресов
    Имитирует реальный случай с ~3.2% плотностью в /24 подсетях
    """
    print(f"Генерация {num_ips} IP-адресов с плотностью ~{density*100:.1f}%...")
    
    ips = set()
    subnets_24 = set()
    
    # Генерируем IP из разных /24 подсетей
    while len(ips) < num_ips:
        # Случайная /24 подсеть
        subnet_24 = ipaddress.IPv4Network(
            f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.0/24",
            strict=False
        )
        
        if subnet_24 in subnets_24:
            continue
        
        subnets_24.add(subnet_24)
        
        # Добавляем несколько IP из этой подсети (имитируя низкую плотность)
        ips_in_subnet = min(
            int(256 * density),
            num_ips - len(ips)
        )
        
        for _ in range(ips_in_subnet):
            if len(ips) >= num_ips:
                break
            
            # Случайный IP в подсети
            ip_int = random.randint(
                int(subnet_24.network_address),
                int(subnet_24.broadcast_address)
            )
            ip = ipaddress.IPv4Address(ip_int)
            ips.add(ip)
    
    # Сохраняем в файл
    with open(output_file, 'w') as f:
        for ip in sorted(ips):
            f.write(f"{ip}\n")
    
    print(f"Сгенерировано {len(ips)} уникальных IP-адресов из {len(subnets_24)} /24 подсетей")
    print(f"Средняя плотность: {len(ips) / (len(subnets_24) * 256) * 100:.2f}%")
    print(f"Результат сохранен в {output_file}")


def generate_dense_ips(num_ips: int, output_file: str, num_subnets: int = None):
    """
    Генерирует плотное распределение IP-адресов
    IP сгруппированы в небольшое количество подсетей
    """
    if num_subnets is None:
        num_subnets = max(1, num_ips // 200)  # ~200 IP на подсеть
    
    print(f"Генерация {num_ips} IP-адресов в {num_subnets} подсетях...")
    
    ips = set()
    subnets = []
    
    # Генерируем подсети
    for _ in range(num_subnets):
        subnet = ipaddress.IPv4Network(
            f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.0/24",
            strict=False
        )
        subnets.append(subnet)
    
    # Распределяем IP по подсетям
    ips_per_subnet = num_ips // num_subnets
    
    for subnet in subnets:
        for _ in range(min(ips_per_subnet, 256)):
            if len(ips) >= num_ips:
                break
            
            ip_int = random.randint(
                int(subnet.network_address),
                int(subnet.broadcast_address)
            )
            ip = ipaddress.IPv4Address(ip_int)
            ips.add(ip)
    
    # Добавляем оставшиеся IP
    while len(ips) < num_ips:
        subnet = random.choice(subnets)
        ip_int = random.randint(
            int(subnet.network_address),
            int(subnet.broadcast_address)
        )
        ip = ipaddress.IPv4Address(ip_int)
        ips.add(ip)
    
    # Сохраняем в файл
    with open(output_file, 'w') as f:
        for ip in sorted(ips):
            f.write(f"{ip}\n")
    
    print(f"Сгенерировано {len(ips)} уникальных IP-адресов в {len(subnets)} подсетях")
    print(f"Результат сохранен в {output_file}")


def main():
    parser = argparse.ArgumentParser(
        description='Генерация тестовых данных IP-адресов',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Примеры:
  # Разреженное распределение (реалистичный случай)
  python3 generate_test_data.py -n 70000 -o test_70k.txt --sparse

  # Плотное распределение
  python3 generate_test_data.py -n 10000 -o test_dense.txt --dense

  # С заданной плотностью
  python3 generate_test_data.py -n 50000 -o test.txt --sparse --density 0.05
        """
    )
    
    parser.add_argument('-n', '--num-ips', type=int, required=True,
                       help='Количество IP-адресов для генерации')
    parser.add_argument('-o', '--output', required=True,
                       help='Выходной файл')
    parser.add_argument('--sparse', action='store_true',
                       help='Разреженное распределение (имитирует реальный случай)')
    parser.add_argument('--dense', action='store_true',
                       help='Плотное распределение (IP сгруппированы)')
    parser.add_argument('--density', type=float, default=0.032,
                       help='Плотность для разреженного распределения (по умолчанию: 0.032 = 3.2%%)')
    parser.add_argument('--seed', type=int, default=None,
                       help='Seed для генератора случайных чисел')
    
    args = parser.parse_args()
    
    if args.seed is not None:
        random.seed(args.seed)
    
    if args.dense:
        generate_dense_ips(args.num_ips, args.output)
    else:
        generate_sparse_ips(args.num_ips, args.output, args.density)


if __name__ == '__main__':
    main()

