""" модуль для описания маршрутного задания
"""
from dataclasses import dataclass
from typing import List
from geopy import Point
import json

@dataclass
class GeoSpecificSpeedLimit:
    """ ограничение скорости в определённой точке маршрута
    действует до следующего скоростного ограничения
    """
    # start_position: Point  # координаты точка начала действия скоростного ограничения
    waypoint_index: int  # индекс путевой точки, начиная с которой действует это ограничение
    speed_limit: int  # ограничение скорости, км/ч


@dataclass
class Mission:
    """ класс описания маршрутного задания
    """
    home: Point  # координата начала маршрута
    waypoints: List[Point]  # координаты путевых точек
    # ограничения скорости на маршруте
    speed_limits: List[GeoSpecificSpeedLimit]
    armed: bool  # поездка разрешена (истина) или запрещена (ложь)

    
def serialize(mission):
    """
    Serialize a route (list of geopy.Point) to a deterministic JSON byte string.
    Sorting the keys ensures consistent serialization.
    """
    mission_data = []
    for point in mission.waypoints:
        point_data = {
            "latitude": point.latitude,
            "longitude": point.longitude,
            "altitude": point.altitude if point.altitude is not None else None
        }
        mission_data.append(point_data)
    for speedlimit in mission.speed_limits:
        speedlimit_data = {
            "start": speedlimit.waypoint_index,
            "speedlimit": speedlimit.speed_limit
        }
        mission_data.append(speedlimit_data)
    return json.dumps(mission_data, sort_keys=True).encode('utf-8')
