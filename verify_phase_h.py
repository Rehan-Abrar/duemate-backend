#!/usr/bin/env python3
"""
Phase H Release Gate Verification Script
Validates auth, isolation, unresolved course persistence, and admin health before production release.

Usage:
    python verify_phase_h.py [BASE_URL]

Default BASE_URL: https://duemate-backend-31qm.onrender.com

Exit code 0 = all checks passed, ready for release
Exit code 1 = one or more checks failed, do not release
"""

import sys
import json
import hashlib
from datetime import datetime, timezone, timedelta
import requests
from typing import Optional, Tuple


class Colors:
    OK = "\033[92m"
    WARN = "\033[93m"
    FAIL = "\033[91m"
    BLUE = "\033[94m"
    RESET = "\033[0m"


def log_header(msg: str):
    print(f"\n{Colors.BLUE}{'=' * 70}")
    print(f"  {msg}")
    print(f"{'=' * 70}{Colors.RESET}\n")


def log_pass(msg: str):
    print(f"{Colors.OK}✓ {msg}{Colors.RESET}")


def log_fail(msg: str):
    print(f"{Colors.FAIL}✗ {msg}{Colors.RESET}")


def log_warn(msg: str):
    print(f"{Colors.WARN}⚠ {msg}{Colors.RESET}")


class VerificationSuite:
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.results = {"passed": 0, "failed": 0, "warnings": 0}
        self.test_accounts = {
            "user_a": {"phone": "923001111111", "password": "TestPass123!"},
            "user_b": {"phone": "923002222222", "password": "TestPass456!"},
        }
        self.tokens = {}
        self.task_ids = {}

    def run_all(self) -> int:
        """Run entire verification suite."""
        log_header("DueMate Phase H Release Gate Verification")

        try:
            self.verify_backend_connectivity()
            self.verify_auth_flow()
            self.verify_data_isolation()
            self.verify_unresolved_persistence()
            self.verify_admin_access()
        except Exception as e:
            log_fail(f"Critical error: {e}")
            self.results["failed"] += 1

        log_header("Verification Summary")
        print(f"Passed: {Colors.OK}{self.results['passed']}{Colors.RESET}")
        print(f"Failed: {Colors.FAIL}{self.results['failed']}{Colors.RESET}")
        print(f"Warnings: {Colors.WARN}{self.results['warnings']}{Colors.RESET}\n")

        if self.results["failed"] > 0:
            log_fail("RELEASE BLOCKED: One or more critical checks failed.")
            return 1
        else:
            log_pass("All checks passed. Ready for production release.")
            return 0

    def verify_backend_connectivity(self):
        """Check backend health and configuration."""
        log_header("1. Backend Connectivity")

        try:
            resp = self.session.get(f"{self.base_url}/health", timeout=10)
            if resp.status_code != 200:
                log_fail(f"Health endpoint returned {resp.status_code}")
                self.results["failed"] += 1
                return

            data = resp.json()
            log_pass(f"Backend is {data.get('status', 'unknown')}")
            self.results["passed"] += 1

            if not data.get("mongo_connected"):
                log_fail("MongoDB not connected")
                self.results["failed"] += 1
                return

            log_pass("MongoDB connected")
            self.results["passed"] += 1

            if not data.get("meta_configured"):
                log_warn("Meta WhatsApp API not fully configured")
                self.results["warnings"] += 1
            else:
                log_pass("Meta WhatsApp API configured")
                self.results["passed"] += 1

        except Exception as e:
            log_fail(f"Health check failed: {e}")
            self.results["failed"] += 1

    def verify_auth_flow(self):
        """Verify signup, login, logout, and session management."""
        log_header("2. Authentication & Session Management")

        for account_key, account in self.test_accounts.items():
            phone = account["phone"]
            password = account["password"]

            # Test signup (or re-login if account exists)
            try:
                resp = self.session.post(
                    f"{self.base_url}/api/auth/signup",
                    json={"phone_number": phone, "password": password},
                    timeout=10,
                )
                # 201 = new, 409 = already exists
                if resp.status_code not in [201, 409]:
                    log_fail(f"{account_key} signup failed: {resp.status_code}")
                    self.results["failed"] += 1
                    continue

                if resp.status_code == 201:
                    log_pass(f"{account_key} account created")
                else:
                    log_pass(f"{account_key} account already exists")
                self.results["passed"] += 1
            except Exception as e:
                log_fail(f"{account_key} signup error: {e}")
                self.results["failed"] += 1
                continue

            # Test login
            try:
                resp = self.session.post(
                    f"{self.base_url}/api/auth/login",
                    json={"phone_number": phone, "password": password},
                    timeout=10,
                )
                if resp.status_code != 200:
                    log_fail(f"{account_key} login failed: {resp.status_code}")
                    self.results["failed"] += 1
                    continue

                data = resp.json()
                token = data.get("token")
                if not token:
                    log_fail(f"{account_key} login returned no token")
                    self.results["failed"] += 1
                    continue

                self.tokens[account_key] = token
                log_pass(f"{account_key} login successful (token received)")
                self.results["passed"] += 1
            except Exception as e:
                log_fail(f"{account_key} login error: {e}")
                self.results["failed"] += 1
                continue

            # Test /api/auth/me
            try:
                resp = self.session.get(
                    f"{self.base_url}/api/auth/me",
                    headers={"Authorization": f"Bearer {self.tokens[account_key]}"},
                    timeout=10,
                )
                if resp.status_code == 200:
                    log_pass(f"{account_key} auth/me endpoint working")
                    self.results["passed"] += 1
                else:
                    log_fail(f"{account_key} auth/me returned {resp.status_code}")
                    self.results["failed"] += 1
            except Exception as e:
                log_fail(f"{account_key} auth/me error: {e}")
                self.results["failed"] += 1

    def verify_data_isolation(self):
        """Verify user A cannot access user B's data."""
        log_header("3. Data Isolation & Access Control")

        if "user_a" not in self.tokens or "user_b" not in self.tokens:
            log_warn("Skipping isolation tests (auth failed)")
            return

        # First, both users fetch their own tasks (should always succeed)
        for account_key in ["user_a", "user_b"]:
            try:
                resp = self.session.get(
                    f"{self.base_url}/api/student/tasks",
                    headers={"Authorization": f"Bearer {self.tokens[account_key]}"},
                    timeout=10,
                )
                if resp.status_code == 200:
                    log_pass(f"{account_key} can fetch own tasks")
                    self.results["passed"] += 1
                    data = resp.json()
                    items = data.get("items", [])
                    if items and len(items) > 0:
                        self.task_ids[account_key] = items[0].get("_id")
                else:
                    log_fail(f"{account_key} fetch own tasks returned {resp.status_code}")
                    self.results["failed"] += 1
            except Exception as e:
                log_fail(f"{account_key} fetch own tasks error: {e}")
                self.results["failed"] += 1

        # Test cross-user isolation: user A tries to access user B's task (should be 404 or 403)
        if "user_a" in self.task_ids and "user_b" in self.tokens:
            try:
                task_id = self.task_ids["user_a"]
                resp = self.session.get(
                    f"{self.base_url}/api/student/tasks/{task_id}",
                    headers={"Authorization": f"Bearer {self.tokens['user_b']}"},
                    timeout=10,
                )
                # Expected: 404 (task not found for this user)
                if resp.status_code == 404:
                    log_pass("Cross-user task isolation enforced (404)")
                    self.results["passed"] += 1
                elif resp.status_code in [403, 401]:
                    log_pass(f"Cross-user task access blocked ({resp.status_code})")
                    self.results["passed"] += 1
                else:
                    log_fail(f"Cross-user task access not properly isolated ({resp.status_code})")
                    self.results["failed"] += 1
            except Exception as e:
                log_fail(f"Cross-user isolation test error: {e}")
                self.results["failed"] += 1

    def verify_unresolved_persistence(self):
        """Verify unresolved course assignment persists and removes from queue after refresh."""
        log_header("4. Unresolved Course Queue Persistence")

        if "user_a" not in self.tokens:
            log_warn("Skipping unresolved tests (auth failed)")
            return

        # Fetch unresolved tasks for user A
        try:
            resp = self.session.get(
                f"{self.base_url}/api/student/tasks?course_unresolved=true&limit=5",
                headers={"Authorization": f"Bearer {self.tokens['user_a']}"},
                timeout=10,
            )
            if resp.status_code != 200:
                log_warn(
                    f"Could not fetch unresolved tasks for user_a ({resp.status_code})"
                )
                self.results["warnings"] += 1
                return

            data = resp.json()
            unresolved_items = [
                item for item in data.get("items", []) if item.get("course_unresolved")
            ]

            if not unresolved_items:
                log_warn("No unresolved tasks available for testing")
                self.results["warnings"] += 1
                return

            task = unresolved_items[0]
            task_id = task.get("_id")
            log_pass(f"Found unresolved task: {task_id}")
            self.results["passed"] += 1

            # Assign a course to this task
            try:
                resp = self.session.post(
                    f"{self.base_url}/api/student/tasks/{task_id}/assign-course",
                    headers={"Authorization": f"Bearer {self.tokens['user_a']}"},
                    json={"course_code": "CS101", "apply_to_source": False},
                    timeout=10,
                )
                if resp.status_code == 200:
                    log_pass(f"Course assigned to task {task_id}")
                    self.results["passed"] += 1
                else:
                    log_fail(
                        f"Failed to assign course ({resp.status_code}): {resp.text[:200]}"
                    )
                    self.results["failed"] += 1
                    return
            except Exception as e:
                log_fail(f"Course assignment error: {e}")
                self.results["failed"] += 1
                return

            # Verify task is no longer in unresolved queue (refresh)
            try:
                resp = self.session.get(
                    f"{self.base_url}/api/student/tasks?course_unresolved=true&limit=5",
                    headers={"Authorization": f"Bearer {self.tokens['user_a']}"},
                    timeout=10,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    unresolved_after = [
                        item for item in data.get("items", []) if item.get("_id") == task_id
                    ]
                    if not unresolved_after:
                        log_pass(f"Task removed from unresolved queue after assignment")
                        self.results["passed"] += 1
                    else:
                        log_fail(
                            f"Task still in unresolved queue after assignment (persistence bug)"
                        )
                        self.results["failed"] += 1
                else:
                    log_fail(f"Could not verify persistence ({resp.status_code})")
                    self.results["failed"] += 1
            except Exception as e:
                log_fail(f"Persistence verification error: {e}")
                self.results["failed"] += 1

        except Exception as e:
            log_fail(f"Unresolved queue test error: {e}")
            self.results["failed"] += 1

    def verify_admin_access(self):
        """Verify admin endpoints return expected data."""
        log_header("5. Admin Operations Access")

        endpoints = [
            ("/api/messages/recent?limit=5", "recent messages"),
            ("/api/delivery-status", "delivery status"),
            ("/api/tasks?course_unresolved=true&limit=5", "unresolved tasks (admin)"),
        ]

        for path, desc in endpoints:
            try:
                resp = self.session.get(f"{self.base_url}{path}", timeout=10)
                if resp.status_code == 200:
                    log_pass(f"Admin endpoint: {desc}")
                    self.results["passed"] += 1
                else:
                    log_warn(f"Admin endpoint returned {resp.status_code}: {desc}")
                    self.results["warnings"] += 1
            except Exception as e:
                log_fail(f"Admin endpoint error ({desc}): {e}")
                self.results["failed"] += 1


def main():
    if len(sys.argv) > 1:
        base_url = sys.argv[1]
    else:
        base_url = "https://duemate-backend-31qm.onrender.com"

    print(f"\nTarget URL: {base_url}")

    suite = VerificationSuite(base_url)
    exit_code = suite.run_all()

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
