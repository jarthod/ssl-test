require "bundler/gem_tasks"
require "rspec/core/rake_task"

RSpec::Core::RakeTask.new(:spec)

desc "Open an irb session preloaded with ssl-test"
task :console do
  sh "irb -rubygems -I lib -r ssl_test.rb"
end

task default: :spec