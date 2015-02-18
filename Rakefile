require "bundler/gem_tasks"
require "rake/testtask"

Rake::TestTask.new do |t|
  t.pattern = "test/*_test.rb"
end

desc "Open an irb session preloaded with ssl-test"
task :console do
  sh "irb -rubygems -I lib -r ssl_test.rb"
end

task default: :test