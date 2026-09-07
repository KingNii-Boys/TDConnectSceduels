# TDSB Timetable School Admin v3

A Node.js/Express student timetable app using the reverse-engineered TDSB Connects API structure, with a school-admin control panel.

## Run locally

1. Copy `.env.example` to `.env`.
2. Set a strong `SESSION_SECRET` and an `ADMIN_PASSWORD`.
3. Run `npm install`.
4. Run `npm start`.
5. Open `http://localhost:3000`.
6. Open `http://localhost:3000/admin` for the admin panel.

### Admin environment variables

```env
PORT=3000
NODE_ENV=development
SESSION_SECRET=replace-with-a-long-random-secret
ADMIN_PASSWORD=replace-with-a-strong-admin-password
```

Do not commit `.env` to GitHub.

## Features

- TDSB student login and timetable retrieval.
- Odd calendar dates = Day 1; even calendar dates = Day 2.
- Lunch displayed from the active schedule.
- Human-readable class times.
- Grade 9–12 schedule selection.
- Admin-managed bell schedules and lunch times.
- Date-range school event schedule overrides by grade.
- Announcements with active dates.
- Full-year calendar and weekly timetable.
- API diagnostics for troubleshooting.

## Deployment note

The Node/Express backend must run on a Node-capable host. GitHub can store the repository, but GitHub Pages cannot run this backend. Do not put TDSB credentials, session secrets, or the admin password in the repository.


## Recurring late starts
By default, the last two Wednesdays of every month use the `late-start` schedule. Period 1 begins at 10:00 AM. The late-start schedule is editable in the admin panel.


## v5 change
Added a dedicated Late Start schedule editor so the selected late-start schedule can be changed independently from the regular bell schedules.

## Student extracurricular activities

Students can add private activities to their timetable from **My extracurricular activities**. Activities support:

- Before school
- During school
- After school
- Weekend (Saturday/Sunday)

Each activity can include a date, start/end time, location, and notes. Activities are stored per student account in `data/student-activities.json` and are not part of the public school configuration. Keep this file out of GitHub; it is included in `.gitignore`.
