require "bundler/gem_tasks"
require "rspec/core/rake_task"
require "rake/extensiontask"



Rake::ExtensionTask.new "rc6" do |ext|
  ext.lib_dir = "lib/rc6"
end

RSpec::Core::RakeTask.new(:spec => [:compile])
task :default => :spec

