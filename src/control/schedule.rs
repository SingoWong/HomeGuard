//! Schedule Manager
//!
//! Handles time-based schedule evaluation for parental control.

use std::collections::HashMap;

use chrono::{Datelike, Local, NaiveTime};
use tracing::debug;

use crate::config::{Schedule, Weekday};

/// Manages time-based schedules
pub struct ScheduleManager {
    /// Schedule definitions keyed by name
    schedules: HashMap<String, ParsedSchedule>,
}

/// Parsed schedule with pre-computed time values
#[derive(Debug, Clone)]
struct ParsedSchedule {
    /// Original schedule config
    config: Schedule,
    /// Parsed start time
    start_time: NaiveTime,
    /// Parsed end time
    end_time: NaiveTime,
    /// Whether schedule crosses midnight
    crosses_midnight: bool,
}

impl ScheduleManager {
    /// Create from config
    pub fn from_config(schedules: &HashMap<String, Schedule>) -> Self {
        let mut parsed = HashMap::new();

        for (name, schedule) in schedules {
            match Self::parse_schedule(schedule) {
                Ok(ps) => {
                    debug!(
                        "Loaded schedule '{}': {:?} {}-{} (crosses_midnight: {})",
                        name, schedule.days, schedule.start, schedule.end, ps.crosses_midnight
                    );
                    parsed.insert(name.clone(), ps);
                }
                Err(e) => {
                    tracing::warn!("Failed to parse schedule '{}': {}", name, e);
                }
            }
        }

        Self { schedules: parsed }
    }

    /// Parse a schedule into a ParsedSchedule
    fn parse_schedule(schedule: &Schedule) -> Result<ParsedSchedule, String> {
        let start_time = NaiveTime::parse_from_str(&schedule.start, "%H:%M")
            .map_err(|e| format!("Invalid start time '{}': {}", schedule.start, e))?;

        let end_time = NaiveTime::parse_from_str(&schedule.end, "%H:%M")
            .map_err(|e| format!("Invalid end time '{}': {}", schedule.end, e))?;

        // Schedule crosses midnight if end is before start
        let crosses_midnight = end_time <= start_time;

        Ok(ParsedSchedule {
            config: schedule.clone(),
            start_time,
            end_time,
            crosses_midnight,
        })
    }

    /// Check if a schedule is currently active
    pub fn is_active(&self, schedule_name: &str) -> bool {
        let Some(schedule) = self.schedules.get(schedule_name) else {
            return false;
        };

        self.is_schedule_active(schedule)
    }

    /// Check if ANY of the given schedules is active
    pub fn any_active(&self, schedule_names: &[String]) -> bool {
        schedule_names.iter().any(|name| self.is_active(name))
    }

    /// Check if all given schedules are active
    pub fn all_active(&self, schedule_names: &[String]) -> bool {
        schedule_names.iter().all(|name| self.is_active(name))
    }

    /// Internal check if a schedule is active
    fn is_schedule_active(&self, schedule: &ParsedSchedule) -> bool {
        let now = Local::now();
        let current_weekday = Weekday::from_chrono(now.weekday());
        let current_time = now.time();

        // For cross-midnight schedules, we need special handling
        if schedule.crosses_midnight {
            self.check_cross_midnight_schedule(schedule, current_weekday, current_time)
        } else {
            self.check_same_day_schedule(schedule, current_weekday, current_time)
        }
    }

    /// Check a schedule that doesn't cross midnight
    fn check_same_day_schedule(
        &self,
        schedule: &ParsedSchedule,
        weekday: Weekday,
        time: NaiveTime,
    ) -> bool {
        // Must be on a scheduled day
        if !schedule.config.days.contains(&weekday) {
            return false;
        }

        // Must be within time range
        time >= schedule.start_time && time < schedule.end_time
    }

    /// Check a schedule that crosses midnight (e.g., 21:00 - 07:00)
    fn check_cross_midnight_schedule(
        &self,
        schedule: &ParsedSchedule,
        weekday: Weekday,
        time: NaiveTime,
    ) -> bool {
        // For cross-midnight schedules:
        // - If time >= start_time, we're in the "evening" portion (same day as start)
        // - If time < end_time, we're in the "morning" portion (day after start)

        if time >= schedule.start_time {
            // Evening portion: check if current day is in schedule
            schedule.config.days.contains(&weekday)
        } else if time < schedule.end_time {
            // Morning portion: check if PREVIOUS day is in schedule
            let prev_day = prev_weekday(weekday);
            schedule.config.days.contains(&prev_day)
        } else {
            // Between end_time and start_time on the same day - not active
            false
        }
    }

    /// Get list of all schedule names
    pub fn schedule_names(&self) -> Vec<&str> {
        self.schedules.keys().map(|s| s.as_str()).collect()
    }

    /// Check if a schedule exists
    pub fn has_schedule(&self, name: &str) -> bool {
        self.schedules.contains_key(name)
    }
}

/// Get the previous weekday
fn prev_weekday(day: Weekday) -> Weekday {
    match day {
        Weekday::Mon => Weekday::Sun,
        Weekday::Tue => Weekday::Mon,
        Weekday::Wed => Weekday::Tue,
        Weekday::Thu => Weekday::Wed,
        Weekday::Fri => Weekday::Thu,
        Weekday::Sat => Weekday::Fri,
        Weekday::Sun => Weekday::Sat,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_schedule(days: Vec<Weekday>, start: &str, end: &str) -> Schedule {
        Schedule {
            days,
            start: start.to_string(),
            end: end.to_string(),
        }
    }

    #[test]
    fn test_parse_schedule_same_day() {
        let schedule = create_test_schedule(
            vec![Weekday::Mon, Weekday::Tue],
            "08:00",
            "16:00",
        );

        let parsed = ScheduleManager::parse_schedule(&schedule).unwrap();
        assert!(!parsed.crosses_midnight);
        assert_eq!(parsed.start_time, NaiveTime::from_hms_opt(8, 0, 0).unwrap());
        assert_eq!(parsed.end_time, NaiveTime::from_hms_opt(16, 0, 0).unwrap());
    }

    #[test]
    fn test_parse_schedule_cross_midnight() {
        let schedule = create_test_schedule(
            vec![Weekday::Mon],
            "21:00",
            "07:00",
        );

        let parsed = ScheduleManager::parse_schedule(&schedule).unwrap();
        assert!(parsed.crosses_midnight);
    }

    #[test]
    fn test_parse_schedule_invalid_time() {
        let schedule = Schedule {
            days: vec![Weekday::Mon],
            start: "25:00".to_string(), // Invalid hour
            end: "08:00".to_string(),
        };

        let result = ScheduleManager::parse_schedule(&schedule);
        assert!(result.is_err());
    }

    #[test]
    fn test_schedule_manager_from_config() {
        let mut schedules = HashMap::new();
        schedules.insert(
            "work_hours".to_string(),
            create_test_schedule(vec![Weekday::Mon, Weekday::Fri], "09:00", "17:00"),
        );

        let manager = ScheduleManager::from_config(&schedules);
        assert!(manager.has_schedule("work_hours"));
        assert!(!manager.has_schedule("nonexistent"));
    }

    #[test]
    fn test_schedule_manager_any_active() {
        let mut schedules = HashMap::new();
        // Create a schedule that's always active
        schedules.insert(
            "always".to_string(),
            create_test_schedule(
                vec![
                    Weekday::Mon, Weekday::Tue, Weekday::Wed,
                    Weekday::Thu, Weekday::Fri, Weekday::Sat, Weekday::Sun,
                ],
                "00:00",
                "23:59",
            ),
        );

        let manager = ScheduleManager::from_config(&schedules);

        // any_active should return true if at least one is active
        assert!(manager.any_active(&["always".to_string(), "nonexistent".to_string()]));
    }

    #[test]
    fn test_prev_weekday() {
        assert_eq!(prev_weekday(Weekday::Mon), Weekday::Sun);
        assert_eq!(prev_weekday(Weekday::Tue), Weekday::Mon);
        assert_eq!(prev_weekday(Weekday::Sun), Weekday::Sat);
    }

    #[test]
    fn test_same_day_schedule_check() {
        let schedule = create_test_schedule(
            vec![Weekday::Mon, Weekday::Tue, Weekday::Wed, Weekday::Thu, Weekday::Fri],
            "08:00",
            "16:00",
        );
        let parsed = ScheduleManager::parse_schedule(&schedule).unwrap();

        let manager = ScheduleManager {
            schedules: HashMap::new(),
        };

        // Within range on a weekday
        let time_in_range = NaiveTime::from_hms_opt(12, 0, 0).unwrap();
        assert!(manager.check_same_day_schedule(&parsed, Weekday::Mon, time_in_range));
        assert!(manager.check_same_day_schedule(&parsed, Weekday::Fri, time_in_range));

        // Outside range
        let time_before = NaiveTime::from_hms_opt(7, 0, 0).unwrap();
        assert!(!manager.check_same_day_schedule(&parsed, Weekday::Mon, time_before));

        let time_after = NaiveTime::from_hms_opt(17, 0, 0).unwrap();
        assert!(!manager.check_same_day_schedule(&parsed, Weekday::Mon, time_after));

        // Weekend - not in schedule
        assert!(!manager.check_same_day_schedule(&parsed, Weekday::Sat, time_in_range));
    }

    #[test]
    fn test_cross_midnight_schedule_check() {
        // Bedtime schedule: 21:00 to 07:00, every day
        let schedule = create_test_schedule(
            vec![
                Weekday::Mon, Weekday::Tue, Weekday::Wed,
                Weekday::Thu, Weekday::Fri, Weekday::Sat, Weekday::Sun,
            ],
            "21:00",
            "07:00",
        );
        let parsed = ScheduleManager::parse_schedule(&schedule).unwrap();
        assert!(parsed.crosses_midnight);

        let manager = ScheduleManager {
            schedules: HashMap::new(),
        };

        // 22:00 Monday (evening portion) - should be active
        let evening = NaiveTime::from_hms_opt(22, 0, 0).unwrap();
        assert!(manager.check_cross_midnight_schedule(&parsed, Weekday::Mon, evening));

        // 06:00 Tuesday (morning portion, Monday night continues) - should be active
        let morning = NaiveTime::from_hms_opt(6, 0, 0).unwrap();
        assert!(manager.check_cross_midnight_schedule(&parsed, Weekday::Tue, morning));

        // 10:00 Tuesday (between end and start) - should NOT be active
        let midday = NaiveTime::from_hms_opt(10, 0, 0).unwrap();
        assert!(!manager.check_cross_midnight_schedule(&parsed, Weekday::Tue, midday));
    }

    #[test]
    fn test_cross_midnight_weekday_limited() {
        // Bedtime only on school nights (Sun-Thu nights, Mon-Fri mornings)
        let schedule = create_test_schedule(
            vec![Weekday::Sun, Weekday::Mon, Weekday::Tue, Weekday::Wed, Weekday::Thu],
            "21:00",
            "07:00",
        );
        let parsed = ScheduleManager::parse_schedule(&schedule).unwrap();

        let manager = ScheduleManager {
            schedules: HashMap::new(),
        };

        // 22:00 Thursday - should be active (Thu is in list)
        let evening = NaiveTime::from_hms_opt(22, 0, 0).unwrap();
        assert!(manager.check_cross_midnight_schedule(&parsed, Weekday::Thu, evening));

        // 06:00 Friday - should be active (Thu night continues into Fri morning)
        let morning = NaiveTime::from_hms_opt(6, 0, 0).unwrap();
        assert!(manager.check_cross_midnight_schedule(&parsed, Weekday::Fri, morning));

        // 22:00 Friday - should NOT be active (Fri not in list)
        assert!(!manager.check_cross_midnight_schedule(&parsed, Weekday::Fri, evening));

        // 06:00 Saturday - should NOT be active (Fri not in list)
        assert!(!manager.check_cross_midnight_schedule(&parsed, Weekday::Sat, morning));
    }
}
