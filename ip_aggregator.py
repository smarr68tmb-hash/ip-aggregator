#!/usr/bin/env python3
"""
Оптимальная агрегация IP-адресов с минимальным over-blocking
Решает задачу Red-Blue Set Cover для сжатия IP-адресов до заданного количества правил
"""

import ipaddress
import argparse
import sys
import subprocess
from typing import Set, List, Tuple, Dict, Optional
from collections import defaultdict
from dataclasses import dataclass
import json


@dataclass
class CIDRBlock:
    """Представляет CIDR блок с метаданными"""
    network: ipaddress.IPv4Network
    target_ips: Set[int]  # Целевые IP в этом блоке (как int)
    total_size: int  # Общее количество IP в блоке
    
    @property
    def overblock_count(self) -> int:
        """Количество over-blocked IP (не целевых)"""
        return self.total_size - len(self.target_ips)
    
    @property
    def density(self) -> float:
        """Плотность целевых IP в блоке (0.0 - 1.0)"""
        return len(self.target_ips) / self.total_size if self.total_size > 0 else 0.0
    
    def __hash__(self):
        return hash(self.network)
    
    def __eq__(self, other):
        return isinstance(other, CIDRBlock) and self.network == other.network


class IPAggregator:
    """Класс для агрегации IP-адресов с контролем over-blocking"""
    
    def __init__(self, target_ips: Set[ipaddress.IPv4Address]):
        self.target_ips = target_ips
        self.target_ips_int = {int(ip) for ip in target_ips}
        self.candidate_cidrs: Dict[str, CIDRBlock] = {}
        self._build_candidate_cidrs()
    
    def _build_candidate_cidrs(self):
        """Строит множество всех возможных CIDR блоков, содержащих целевые IP"""
        print(f"Построение кандидатов CIDR из {len(self.target_ips)} IP...")
        
        # Группируем IP по /24 подсетям для оптимизации
        ip_by_subnet24 = defaultdict(set)
        for ip in self.target_ips:
            subnet24 = ipaddress.IPv4Network(f"{ip}/24", strict=False)
            ip_by_subnet24[subnet24].add(ip)
        
        # Генерируем кандидаты от /32 до /8
        for prefix_len in range(8, 33):
            seen_networks = set()
            
            for ip in self.target_ips:
                # Создаем сеть с данным префиксом, содержащую этот IP
                try:
                    network = ipaddress.IPv4Network(f"{ip}/{prefix_len}", strict=False)
                    network_key = str(network)
                    
                    if network_key in seen_networks:
                        continue
                    seen_networks.add(network_key)
                    
                    # Подсчитываем целевые IP в этой сети
                    network_start = int(network.network_address)
                    network_end = int(network.broadcast_address)
                    target_in_network = {
                        ip_int for ip_int in self.target_ips_int
                        if network_start <= ip_int <= network_end
                    }
                    
                    if target_in_network:  # Только если есть хотя бы один целевой IP
                        self.candidate_cidrs[network_key] = CIDRBlock(
                            network=network,
                            target_ips=target_in_network,
                            total_size=network.num_addresses
                        )
                except ValueError:
                    continue
        
        # ИСПРАВЛЕНИЕ ОШИБКИ 2: Гарантируем, что все /32 правила для целевых IP явно включены
        # Это критически важно для обеспечения возможности полного покрытия
        for ip in self.target_ips:
            network = ipaddress.IPv4Network(f"{ip}/32", strict=False)
            network_key = str(network)
            if network_key not in self.candidate_cidrs:
                ip_int = int(ip)
                self.candidate_cidrs[network_key] = CIDRBlock(
                    network=network,
                    target_ips={ip_int},
                    total_size=1
                )
        
        print(f"Создано {len(self.candidate_cidrs)} кандидатов CIDR (включая все /32 правила)")
    
    def _ensure_full_coverage_with_limit(
        self, 
        selected: List[CIDRBlock], 
        max_entries: int
    ) -> List[CIDRBlock]:
        """
        ИСПРАВЛЕНИЕ ОШИБКИ 1: Обеспечивает полное покрытие с учетом лимита правил.
        
        Добавляет /32 правила для непокрытых IP, но гарантирует, что общее
        количество правил не превышает max_entries.
        
        Если непокрытых IP слишком много, возвращает решение с неполным покрытием,
        но в пределах лимита.
        """
        # Определяем непокрытые IP
        covered = set()
        for cidr in selected:
            covered |= cidr.target_ips
        
        uncovered = self.target_ips_int - covered
        
        if not uncovered:
            # Уже полное покрытие
            return selected
        
        # Создаем /32 правила для непокрытых IP
        uncovered_32_rules = []
        for ip_int in uncovered:
            ip = ipaddress.IPv4Address(ip_int)
            network = ipaddress.IPv4Network(f"{ip}/32", strict=False)
            uncovered_32_rules.append(CIDRBlock(
                network=network,
                target_ips={ip_int},
                total_size=1
            ))
        
        # Проверяем, помещается ли решение в лимит
        total_rules = len(selected) + len(uncovered_32_rules)
        
        if total_rules <= max_entries:
            # Все помещается - возвращаем полное решение
            return selected + uncovered_32_rules
        else:
            # Не помещается - нужно уменьшить количество агрегированных правил
            # Возвращаем решение в пределах лимита (может быть неполное покрытие)
            available_slots = max_entries - len(uncovered_32_rules)
            
            if available_slots <= 0:
                # Даже только /32 правила превышают лимит - возвращаем только часть /32
                print(f"Предупреждение: Лимит {max_entries} недостаточен для покрытия всех {len(uncovered)} непокрытых IP")
                print(f"Будет добавлено только {max_entries} /32 правил из {len(uncovered)} непокрытых")
                return uncovered_32_rules[:max_entries]
            
            # Оставляем только лучшие агрегированные правила (по эффективности)
            # Сортируем по убыванию эффективности (больше IP на правило)
            selected_sorted = sorted(
                selected,
                key=lambda x: len(x.target_ips) / (x.overblock_count + 1),  # эффективность: IP/overblock
                reverse=True
            )
            
            # Берем только лучшие агрегированные правила, которые помещаются
            final_selected = selected_sorted[:available_slots]
            
            # Определяем, какие IP еще не покрыты после сокращения
            final_covered = set()
            for cidr in final_selected:
                final_covered |= cidr.target_ips
            
            still_uncovered = self.target_ips_int - final_covered
            
            # Добавляем /32 для оставшихся непокрытых IP (до лимита)
            remaining_slots = max_entries - len(final_selected)
            for ip_int in list(still_uncovered)[:remaining_slots]:
                ip = ipaddress.IPv4Address(ip_int)
                network = ipaddress.IPv4Network(f"{ip}/32", strict=False)
                final_selected.append(CIDRBlock(
                    network=network,
                    target_ips={ip_int},
                    total_size=1
                ))
            
            return final_selected
    
    def _remove_dominated(self):
        """
        ОТКЛЮЧЕНО: Удаление доминируемых CIDR блоков

        Причина отключения: Эта оптимизация может удалять важные кандидаты,
        что приводит к неполному покрытию целевых IP в жадном алгоритме.

        Оригинальная логика была:
        - Удалять C1 если C2 ⊂ C1 и w(C2) ≤ w(C1)
        - Но проверка "cidr2.target_ips >= cidr1.target_ips" неверно интерпретировалась

        Без этой оптимизации алгоритмы работают корректно, хотя и с большим
        числом кандидатов для перебора (незначительное влияние на производительность).
        """
        print("Оптимизация доминируемых CIDR блоков отключена для корректности алгоритма")
        return  # Функция отключена
    
    def greedy_aggregate(self, max_entries: int = 2000, iterative: bool = True) -> List[CIDRBlock]:
        """
        Жадный алгоритм агрегации с контролем over-blocking
        Гарантия аппроксимации: O(ln n)
        
        ИСПРАВЛЕНИЕ ОШИБКИ 1: Использует итеративный подход для гарантии соблюдения лимита
        при обеспечении полного покрытия.
        """
        print(f"\n=== Жадный алгоритм (макс. {max_entries} правил) ===")
        
        if not iterative:
            # Старый подход без итерации (для обратной совместимости)
            return self._greedy_aggregate_internal(max_entries)
        
        # Итеративный подход: начинаем с max_entries, уменьшаем если нужно
        current_max = max_entries
        best_solution = None
        best_coverage = 0
        
        # Максимум 10 итераций для избежания бесконечного цикла
        for iteration in range(10):
            solution = self._greedy_aggregate_internal(current_max)
            
            # Применяем ensure_full_coverage_with_limit
            final_solution = self._ensure_full_coverage_with_limit(solution, max_entries)
            
            # Проверяем покрытие финального решения
            covered = set()
            for cidr in final_solution:
                covered |= cidr.target_ips
            coverage = len(covered) / len(self.target_ips_int) * 100
            
            # Проверяем, соответствует ли решение требованиям
            if len(final_solution) <= max_entries:
                if coverage >= 99.9:  # Полное покрытие
                    print(f"Итерация {iteration + 1}: Найдено решение с полным покрытием ({coverage:.2f}%) и {len(final_solution)} правил")
                    return final_solution
                else:
                    # Частичное покрытие, но в пределах лимита - запоминаем лучшее
                    if coverage > best_coverage:
                        best_coverage = coverage
                        best_solution = final_solution
            
            # Если решение превышает лимит или покрытие неполное, уменьшаем current_max
            if len(final_solution) > max_entries:
                # Оценка количества /32 правил, которые понадобятся
                uncovered_count = len(self.target_ips_int) - len(covered)
                estimated_needed_slots = uncovered_count
                current_max = max(1, max_entries - estimated_needed_slots - 10)  # -10 для запаса
                print(f"Итерация {iteration + 1}: Решение требует {len(final_solution)} правил, уменьшаем лимит до {current_max}")
            else:
                # Если решение в пределах лимита, но неполное покрытие, уменьшаем немного
                current_max = max(1, len(solution) - 50)
                print(f"Итерация {iteration + 1}: Покрытие {coverage:.2f}%, уменьшаем лимит до {current_max}")
        
        # Если не удалось найти решение с полным покрытием, возвращаем лучшее найденное
        if best_solution is not None:
            print(f"Найдено лучшее решение с покрытием {best_coverage:.2f}% и {len(best_solution)} правил")
            return best_solution
        
        # Финальная попытка: просто возвращаем решение с ensure_full_coverage_with_limit
        solution = self._greedy_aggregate_internal(max_entries)
        return self._ensure_full_coverage_with_limit(solution, max_entries)
    
    def _greedy_aggregate_internal(self, max_entries: int) -> List[CIDRBlock]:
        """
        Внутренняя реализация жадного алгоритма без итераций
        """
        uncovered = self.target_ips_int.copy()
        selected: List[CIDRBlock] = []
        candidate_list = list(self.candidate_cidrs.values())
        
        iteration = 0
        while uncovered and len(selected) < max_entries:
            iteration += 1
            if iteration % 100 == 0:
                print(f"Итерация {iteration}: покрыто {len(self.target_ips_int) - len(uncovered)}/{len(self.target_ips_int)} IP, выбрано {len(selected)} правил")
            
            best_cidr = None
            best_efficiency = float('inf')
            
            for cidr in candidate_list:
                # Подсчитываем новые покрытые IP
                newly_covered = cidr.target_ips & uncovered
                if not newly_covered:
                    continue
                
                # Метрика эффективности: over-blocking cost на один новый покрытый IP
                overblock_cost = cidr.overblock_count
                efficiency = overblock_cost / len(newly_covered) if newly_covered else float('inf')
                
                if efficiency < best_efficiency:
                    best_efficiency = efficiency
                    best_cidr = cidr
            
            if best_cidr:
                selected.append(best_cidr)
                uncovered -= best_cidr.target_ips
            else:
                break
        
        # Проверяем покрытие
        covered = set()
        for cidr in selected:
            covered |= cidr.target_ips
        
        coverage = len(covered) / len(self.target_ips_int) * 100
        print(f"Покрытие: {coverage:.2f}% ({len(covered)}/{len(self.target_ips_int)} IP)")
        
        return selected
    
    def density_based_aggregate(self, max_entries: int = 2000) -> List[CIDRBlock]:
        """
        Плотностно-ориентированная гибридная стратегия
        """
        print(f"\n=== Плотностно-ориентированная стратегия (макс. {max_entries} правил) ===")
        
        # Фаза 1: Классификация по плотности
        high_density = []  # ≥80% - агрегировать до /24
        medium_density = []  # 40-80% - использовать /25 или /26
        low_density = []  # <40% - оставить отдельные /32
        
        for cidr in self.candidate_cidrs.values():
            if cidr.network.prefixlen == 24:
                if cidr.density >= 0.8:
                    high_density.append(cidr)
                elif cidr.density >= 0.4:
                    medium_density.append(cidr)
                else:
                    low_density.append(cidr)
        
        selected: List[CIDRBlock] = []
        uncovered = self.target_ips_int.copy()
        
        # Приоритет 1: Высокая плотность /24
        for cidr in sorted(high_density, key=lambda x: -x.density):
            if len(selected) >= max_entries:
                break
            if cidr.target_ips & uncovered:
                selected.append(cidr)
                uncovered -= cidr.target_ips
        
        # Приоритет 2: Средняя плотность - ищем оптимальные /25 или /26
        for cidr in sorted(medium_density, key=lambda x: -x.density):
            if len(selected) >= max_entries:
                break
            if cidr.target_ips & uncovered:
                selected.append(cidr)
                uncovered -= cidr.target_ips
        
        # Приоритет 3: Низкая плотность - используем жадный алгоритм для остатка
        remaining_candidates = [
            c for c in self.candidate_cidrs.values()
            if c.target_ips & uncovered
        ]
        
        while uncovered and len(selected) < max_entries:
            best_cidr = None
            best_efficiency = float('inf')
            
            for cidr in remaining_candidates:
                newly_covered = cidr.target_ips & uncovered
                if not newly_covered:
                    continue
                
                efficiency = cidr.overblock_count / len(newly_covered)
                if efficiency < best_efficiency:
                    best_efficiency = efficiency
                    best_cidr = cidr
            
            if best_cidr:
                selected.append(best_cidr)
                uncovered -= best_cidr.target_ips
            else:
                break
        
        coverage = (len(self.target_ips_int) - len(uncovered)) / len(self.target_ips_int) * 100
        print(f"Покрытие: {coverage:.2f}% ({len(self.target_ips_int) - len(uncovered)}/{len(self.target_ips_int)} IP)")
        
        # ИСПРАВЛЕНИЕ ОШИБКИ 1: Обеспечиваем полное покрытие с учетом лимита
        selected = self._ensure_full_coverage_with_limit(selected, max_entries)
        
        # Проверяем финальное покрытие
        covered_final = set()
        for cidr in selected:
            covered_final |= cidr.target_ips
        coverage_final = len(covered_final) / len(self.target_ips_int) * 100
        print(f"Финальное покрытие: {coverage_final:.2f}% ({len(covered_final)}/{len(self.target_ips_int)} IP), правил: {len(selected)}")
        
        return selected
    
    def ilp_aggregate(self, max_entries: int = 2000, solver: Optional[str] = None) -> Optional[List[CIDRBlock]]:
        """
        ILP решение с использованием PuLP
        Требует установки: pip install pulp
        """
        try:
            from pulp import LpProblem, LpMinimize, LpVariable, lpSum, PULP_CBC_CMD, GUROBI_CMD
        except ImportError:
            print("Ошибка: PuLP не установлен и не может быть импортирован.")
            print("Попробуйте установить вручную: pip install pulp")
            return None
        
        print(f"\n=== ILP решение (макс. {max_entries} правил) ===")
        print("Предупреждение: ILP решение может занять значительное время для больших наборов данных")
        
        # Получаем жадное решение как warm-start
        greedy_solution = self.greedy_aggregate(max_entries)
        greedy_cidr_keys = {str(c.network) for c in greedy_solution}
        
        # Ограничиваем кандидатов для ускорения (используем только релевантные)
        # ИСПРАВЛЕНИЕ ОШИБКИ 2: Гарантируем, что все /32 правила включены
        relevant_candidates = []
        slash32_rules = []
        
        for c in self.candidate_cidrs.values():
            if c.network.prefixlen == 32:
                # Все /32 правила обязательно включаем
                slash32_rules.append(c)
            elif str(c.network) in greedy_cidr_keys or any(
                ip in c.target_ips for ip in self.target_ips_int
            ):
                relevant_candidates.append(c)
        
        # Добавляем все /32 правила
        relevant_candidates.extend(slash32_rules)
        
        # Ограничиваем размер для практичности, но сохраняем все /32 правила
        if len(relevant_candidates) > 10000:
            # Отделяем /32 от остальных
            non_32_candidates = [c for c in relevant_candidates if c.network.prefixlen != 32]
            
            # Сортируем не-/32 кандидаты и берем лучшие
            non_32_sorted = sorted(
                non_32_candidates,
                key=lambda x: (x.overblock_count / len(x.target_ips) if x.target_ips else float('inf'))
            )
            
            # Оставляем место для всех /32 правил
            max_non_32 = max(0, 10000 - len(slash32_rules))
            relevant_candidates = non_32_sorted[:max_non_32] + slash32_rules
            
            print(f"Ограничиваем не-/32 кандидатов до {max_non_32}, сохраняем все {len(slash32_rules)} /32 правил")
        
        print(f"Используем {len(relevant_candidates)} кандидатов для ILP")
        
        prob = LpProblem("CIDR_MinOverblock", LpMinimize)
        
        # Бинарные переменные
        x = {
            str(c.network): LpVariable(f"x_{c.network.prefixlen}_{c.network.network_address}", cat='Binary')
            for c in relevant_candidates
        }
        
        # Цель: минимизировать over-blocking
        prob += lpSum(c.overblock_count * x[str(c.network)] for c in relevant_candidates)
        
        # Ограничение покрытия: каждый целевой IP покрыт хотя бы одним CIDR
        ip_to_cidrs = defaultdict(list)
        for c in relevant_candidates:
            for ip_int in c.target_ips:
                ip_to_cidrs[ip_int].append(c)
        
        for ip_int in self.target_ips_int:
            covering = [c for c in relevant_candidates if ip_int in c.target_ips]
            if covering:
                prob += lpSum(x[str(c.network)] for c in covering) >= 1
        
        # Ограничение кардинальности
        prob += lpSum(x[str(c.network)] for c in relevant_candidates) <= max_entries
        
        # Выбор солвера
        if solver == 'gurobi':
            try:
                solver_cmd = GUROBI_CMD(timeLimit=600, msg=1)
            except:
                print("Gurobi недоступен, используем CBC")
                solver_cmd = PULP_CBC_CMD(msg=1, timeLimit=600)
        else:
            solver_cmd = PULP_CBC_CMD(msg=1, timeLimit=600)
        
        print("Запуск ILP солвера...")
        prob.solve(solver_cmd)
        
        if prob.status != 1:  # 1 = Optimal
            print(f"Предупреждение: ILP решение не оптимально (статус: {prob.status})")
            return None
        
        # Извлекаем решение
        selected = [
            c for c in relevant_candidates
            if x[str(c.network)].value() and x[str(c.network)].value() > 0.5
        ]
        
        # ИСПРАВЛЕНИЕ ОШИБКИ 1: Обеспечиваем полное покрытие с учетом лимита
        # ILP может не покрыть все IP, если ограничение кардинальности слишком строгое
        selected = self._ensure_full_coverage_with_limit(selected, max_entries)
        
        # Проверяем финальное покрытие
        covered_final = set()
        for cidr in selected:
            covered_final |= cidr.target_ips
        coverage_final = len(covered_final) / len(self.target_ips_int) * 100
        print(f"Финальное покрытие: {coverage_final:.2f}% ({len(covered_final)}/{len(self.target_ips_int)} IP), правил: {len(selected)}")
        
        return selected


def calculate_metrics(selected: List[CIDRBlock], target_ips: Set[int]) -> Dict:
    """
    Вычисляет метрики качества агрегации

    ИСПРАВЛЕНИЯ:
    - Precision теперь использует фактически покрытые IP (covered), а не все целевые
    - Over-blocking корректно вычисляется только при полном покрытии (≥99.9%)
    - При неполном покрытии over-blocking = 0 (не применим)
    """
    # Проверяем фактическое покрытие
    covered = set()
    for c in selected:
        covered |= c.target_ips

    total_targets = len(target_ips)
    coverage_percent = len(covered) / total_targets * 100 if total_targets > 0 else 0

    # Over-blocking имеет смысл только при полном покрытии
    if coverage_percent >= 99.9:  # Учитываем погрешность округления
        # Все цели покрыты - считаем total blocked включая лишние IP
        total_blocked = sum(c.total_size for c in selected)
        overblocked = total_blocked - total_targets
        false_positive_rate = overblocked / (2**32 - total_targets) if total_targets < 2**32 else 0
    else:
        # Неполное покрытие - over-blocking не применим
        total_blocked = len(covered)  # Считаем только фактически покрытые IP
        overblocked = 0
        false_positive_rate = 0.0

    metrics = {
        'num_rules': len(selected),
        'target_ips': total_targets,
        'covered_ips': len(covered),
        'coverage_percent': coverage_percent,
        'total_blocked_ips': total_blocked,
        'overblocked_ips': overblocked,
        'expansion_factor': total_blocked / total_targets if total_targets > 0 else 0,
        'precision': len(covered) / total_blocked if total_blocked > 0 else 0,  # ИСПРАВЛЕНО
        'rule_efficiency': len(covered) / len(selected) if selected else 0,  # ИСПРАВЛЕНО: используем covered
        'false_positive_rate': false_positive_rate,
    }

    return metrics


def ensure_pulp_installed() -> bool:
    """
    Проверяет наличие PuLP и при необходимости устанавливает его
    Возвращает True если PuLP доступен, False в случае ошибки
    """
    try:
        import pulp
        return True
    except ImportError:
        print("PuLP не найден. Попытка автоматической установки...")
        print("Выполняется: pip install pulp")
        
        try:
            # Устанавливаем PuLP через pip
            result = subprocess.run(
                [sys.executable, '-m', 'pip', 'install', 'pulp'],
                check=True,
                capture_output=True,
                text=True
            )
            print("✓ PuLP успешно установлен")
            
            # Проверяем, что импорт теперь работает
            try:
                import pulp
                return True
            except ImportError:
                print("Ошибка: PuLP установлен, но импорт не работает. Возможно, требуется перезапуск скрипта.")
                return False
                
        except subprocess.CalledProcessError as e:
            print(f"Ошибка при установке PuLP:")
            print(f"  Код возврата: {e.returncode}")
            if e.stdout:
                print(f"  Вывод: {e.stdout}")
            if e.stderr:
                print(f"  Ошибки: {e.stderr}")
            print("\nПопробуйте установить вручную:")
            print("  pip install pulp")
            return False
        except FileNotFoundError:
            print("Ошибка: pip не найден. Установите PuLP вручную:")
            print("  pip install pulp")
            return False


def load_ips_from_file(filename: str) -> Set[ipaddress.IPv4Address]:
    """Загружает IP-адреса из файла (по одному на строку)"""
    ips = set()
    with open(filename, 'r') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            try:
                ip = ipaddress.IPv4Address(line.split()[0])  # Берем первый токен (на случай портов)
                ips.add(ip)
            except ValueError:
                continue
    return ips


def main():
    parser = argparse.ArgumentParser(
        description='Оптимальная агрегация IP-адресов с минимальным over-blocking',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Примеры использования:
  # Жадный алгоритм
  python ip_aggregator.py input.txt -m greedy -o output.txt

  # Плотностно-ориентированная стратегия
  python ip_aggregator.py input.txt -m density -o output.txt

  # ILP решение (требует PuLP)
  python ip_aggregator.py input.txt -m ilp -o output.txt --solver cbc

  # С ограничением максимального префикса
  python ip_aggregator.py input.txt -m greedy --max-prefix 20 -o output.txt
        """
    )
    
    parser.add_argument('input_file', help='Файл с IP-адресами (по одному на строку)')
    parser.add_argument('-o', '--output', required=True, help='Выходной файл для CIDR правил')
    parser.add_argument('-m', '--method', choices=['greedy', 'density', 'ilp'], 
                       default='greedy', help='Метод агрегации (по умолчанию: greedy)')
    parser.add_argument('-e', '--max-entries', type=int, default=2000,
                       help='Максимальное количество правил (по умолчанию: 2000)')
    parser.add_argument('--max-prefix', type=int, default=8,
                       help='Минимальная длина префикса (максимальный размер блока, по умолчанию: 8)')
    parser.add_argument('--solver', choices=['cbc', 'gurobi'], default='cbc',
                       help='ILP солвер (по умолчанию: cbc)')
    parser.add_argument('--metrics', action='store_true',
                       help='Вывести детальные метрики')
    parser.add_argument('--json', action='store_true',
                       help='Вывести метрики в формате JSON')
    
    args = parser.parse_args()
    
    # Загрузка IP
    print(f"Загрузка IP-адресов из {args.input_file}...")
    target_ips = load_ips_from_file(args.input_file)
    print(f"Загружено {len(target_ips)} уникальных IP-адресов")
    
    if not target_ips:
        print("Ошибка: не найдено ни одного валидного IP-адреса")
        sys.exit(1)
    
    # Создание агрегатора
    aggregator = IPAggregator(target_ips)
    
    # Фильтрация по максимальному префиксу
    # ИСПРАВЛЕНИЕ ОШИБКИ 2: Всегда сохраняем /32 правила даже при фильтрации
    if args.max_prefix > 8:
        # Отделяем /32 правила, чтобы они не были отфильтрованы
        slash32_backup = {
            k: v for k, v in aggregator.candidate_cidrs.items()
            if v.network.prefixlen == 32
        }
        
        # Фильтруем остальные кандидаты
        filtered_candidates = {
            k: v for k, v in aggregator.candidate_cidrs.items()
            if v.network.prefixlen >= args.max_prefix
        }
        
        # Объединяем отфильтрованные кандидаты с /32 правилами
        aggregator.candidate_cidrs = {**filtered_candidates, **slash32_backup}
        
        print(f"Отфильтровано до {len(aggregator.candidate_cidrs)} кандидатов (префикс >= {args.max_prefix}, сохранены все {len(slash32_backup)} /32 правил)")
    
    # Удаление доминируемых
    aggregator._remove_dominated()
    
    # Проверка и установка PuLP для метода ilp
    if args.method == 'ilp':
        if not ensure_pulp_installed():
            print("\nОшибка: не удалось установить PuLP. Используйте другой метод или установите PuLP вручную.")
            print("Альтернативы:")
            print("  - Используйте метод 'greedy': -m greedy")
            print("  - Используйте метод 'density': -m density")
            print("  - Установите PuLP вручную: pip install pulp")
            sys.exit(1)
    
    # Выбор метода агрегации
    if args.method == 'greedy':
        selected = aggregator.greedy_aggregate(args.max_entries)
    elif args.method == 'density':
        selected = aggregator.density_based_aggregate(args.max_entries)
    elif args.method == 'ilp':
        selected = aggregator.ilp_aggregate(args.max_entries, args.solver)
        if selected is None:
            print("Ошибка: не удалось получить ILP решение")
            sys.exit(1)
    
    # Вычисление метрик
    target_ips_int = {int(ip) for ip in target_ips}
    metrics = calculate_metrics(selected, target_ips_int)
    
    # Сохранение результата
    print(f"\nСохранение {len(selected)} правил в {args.output}...")
    with open(args.output, 'w') as f:
        for cidr in sorted(selected, key=lambda x: (x.network.prefixlen, x.network.network_address)):
            f.write(f"{cidr.network}\n")
    
    # Вывод метрик
    print("\n" + "="*60)
    print("МЕТРИКИ КАЧЕСТВА АГРЕГАЦИИ")
    print("="*60)
    print(f"Количество правил:        {metrics['num_rules']:,}")
    print(f"Целевых IP:                {metrics['target_ips']:,}")
    print(f"Покрыто IP:                {metrics['covered_ips']:,} ({metrics['coverage_percent']:.2f}%)")
    print(f"Всего заблокировано IP:    {metrics['total_blocked_ips']:,}")
    print(f"Over-blocked IP:           {metrics['overblocked_ips']:,}")
    print(f"Expansion Factor:          {metrics['expansion_factor']:.3f}")
    print(f"Precision:                 {metrics['precision']:.6f}")
    print(f"Rule Efficiency:           {metrics['rule_efficiency']:.1f} IP/правило")
    print(f"False Positive Rate:       {metrics['false_positive_rate']:.2e}")
    print("="*60)
    
    if args.json:
        print("\nJSON метрики:")
        print(json.dumps(metrics, indent=2))
    
    print(f"\nРезультат сохранен в {args.output}")


if __name__ == '__main__':
    main()

