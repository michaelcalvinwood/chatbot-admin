#!/bin/bash

rsync -a --exclude 'node_modules' . root@admin.instantchatbot.net:/home/admin/
