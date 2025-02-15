#!/bin/sh

mkdir /opt/scoring
cp install/background.jpeg /opt/scoring/
cp install/style.css /opt/scoring/
cp install/run.sh /opt/scoring/
cp install/ScoringEngine.service /etc/systemd/system/
cp engine /opt/scoring/engine
chmod +x /opt/scoring/engine
chmod +x /opt/scoring/run.sh
