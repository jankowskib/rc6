require "bundler/gem_tasks"
require "rspec/core/rake_task"
require "rake/extensiontask"

RSpec::Core::RakeTask.new(:spec)

task :default => :spec

Rake::ExtensionTask.new "rc6" do |ext|
  ext.lib_dir = "lib/rc6"
end
